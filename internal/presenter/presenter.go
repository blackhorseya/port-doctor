// Package presenter renders a port-doctor report for humans in a terminal.
package presenter

import (
	"cmp"
	"fmt"
	"io"
	"strconv"
	"strings"

	"charm.land/lipgloss/v2"

	"github.com/blackhorseya/port-doctor/internal/doctor"
)

var (
	availableStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Green)
	inUseStyle     = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Red)
	headingStyle   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Blue)
	commandStyle   = lipgloss.NewStyle().Foreground(lipgloss.Cyan)
	dimStyle       = lipgloss.NewStyle().Faint(true)
)

// Render writes the report to w. Colors are used only when w is a terminal
// that supports them; otherwise the output is plain text.
func Render(w io.Writer, r doctor.Report) error {
	var sections []string
	if r.Status == doctor.StatusAvailable {
		sections = append(sections, availableStyle.Render(fmt.Sprintf("✓ Port %d is available", r.Port)))
	} else {
		sections = append(sections, inUseStyle.Render(fmt.Sprintf("✗ Port %d is in use", r.Port)))
		for _, occ := range r.Occupants {
			sections = append(sections, process(occ), network(occ))
		}
		for _, ct := range r.Containers {
			sections = append(sections, container(ct))
		}
		if r.Diagnosis != "" {
			sections = append(sections, lines(headingStyle.Render("Diagnosis"), "  "+r.Diagnosis))
		}
		if s := suggestions(r.Suggestions); s != "" {
			sections = append(sections, s)
		}
	}
	if len(r.Notes) > 0 {
		sections = append(sections, notes(r.Notes))
	}

	_, err := lipgloss.Fprint(w, strings.Join(sections, "\n\n")+"\n")
	return err
}

// RenderOverview writes the port overview to w as a table with one line
// per port and process. Colors are used only when w is a terminal that
// supports them; otherwise the output is plain, space-padded text.
func RenderOverview(w io.Writer, o doctor.Overview) error {
	var sections []string
	if len(o.Rows) == 0 {
		sections = append(sections, "No TCP port is listening.")
	} else {
		sections = append(sections, overviewTable(o.Rows))
	}
	if len(o.Notes) > 0 {
		sections = append(sections, notes(o.Notes))
	}

	_, err := lipgloss.Fprint(w, strings.Join(sections, "\n\n")+"\n")
	return err
}

var overviewColumns = []string{"PORT", "BIND", "PID", "PROCESS", "USER", "CONTAINER"}

// cell is one table value with an optional style. The style is applied
// after the column width has been measured on the plain text, so escape
// codes never shift a column in a real terminal.
type cell struct {
	text   string
	render func(...string) string // a lipgloss.Style's Render, or nil for plain text
}

func plain(text string) cell {
	return cell{text: text}
}

func unknown() cell {
	return cell{text: "-", render: dimStyle.Render}
}

// overviewTable lays out rows in columns two spaces apart, each as wide as
// its widest value, with the last column unpadded.
func overviewTable(rows []doctor.Row) string {
	header := make([]cell, 0, len(overviewColumns))
	for _, h := range overviewColumns {
		header = append(header, cell{text: h, render: headingStyle.Render})
	}
	table := [][]cell{header}
	for _, r := range rows {
		table = append(table, overviewCells(r))
	}

	widths := make([]int, len(overviewColumns))
	for _, row := range table {
		for i, c := range row {
			widths[i] = max(widths[i], lipgloss.Width(c.text))
		}
	}
	out := make([]string, 0, len(table))
	for _, row := range table {
		out = append(out, tableLine(row, widths))
	}
	return lines(out...)
}

func overviewCells(r doctor.Row) []cell {
	pid, proc, user := unknown(), unknown(), unknown()
	if r.Process.PID != 0 {
		pid = plain(strconv.Itoa(r.Process.PID))
	}
	switch {
	case r.Exited:
		proc = cell{text: "(exited)", render: dimStyle.Render}
	case r.Process.Name != "":
		proc = plain(r.Process.Name)
	}
	if r.Process.User != "" {
		user = plain(r.Process.User)
	}
	return []cell{plain(strconv.Itoa(r.Port)), plain(r.Bind), pid, proc, user, plain(containersText(r.Containers))}
}

func containersText(cs []doctor.Container) string {
	parts := make([]string, 0, len(cs))
	for _, ct := range cs {
		parts = append(parts, fmt.Sprintf("%s (%s)", cmp.Or(ct.Name, ct.ID), ct.Runtime))
	}
	return strings.Join(parts, ", ")
}

// tableLine pads every cell but the last to its column width plus the
// two-space gutter, measuring the plain text and styling afterwards. An
// empty last cell leaves no trailing spaces.
func tableLine(row []cell, widths []int) string {
	var b strings.Builder
	for i, c := range row {
		text := c.text
		if c.render != nil {
			text = c.render(c.text)
		}
		b.WriteString(text)
		if i < len(row)-1 {
			b.WriteString(strings.Repeat(" ", widths[i]-lipgloss.Width(c.text)+2))
		}
	}
	return strings.TrimRight(b.String(), " ")
}

func notes(ns []string) string {
	out := make([]string, 0, len(ns))
	for _, n := range ns {
		out = append(out, dimStyle.Render(n))
	}
	return lines(out...)
}

func process(occ doctor.Occupant) string {
	return lines(
		headingStyle.Render("Process"),
		field("PID", pidText(occ)),
		field("Name", nameText(occ)),
		field("User", cmp.Or(occ.Process.User, unavailable())),
	)
}

func network(occ doctor.Occupant) string {
	out := []string{headingStyle.Render("Network")}
	if len(occ.Listeners) > 0 {
		out = append(out, field("Protocol", string(occ.Listeners[0].Protocol)))
	}
	for _, l := range occ.Listeners {
		out = append(out, field("Address", l.Addr.String()))
	}
	return lines(out...)
}

func container(ct doctor.Container) string {
	out := []string{
		headingStyle.Render("Container"),
		field("Runtime", cmp.Or(ct.Runtime, unavailable())),
		field("Name", cmp.Or(ct.Name, unavailable())),
		field("Image", cmp.Or(ct.Image, unavailable())),
	}
	if ct.Compose.Project != "" {
		out = append(out, field("Compose", composeText(ct.Compose)))
	}
	for _, m := range ct.Mappings {
		out = append(out, field("Mapping", fmt.Sprintf("%s → %d/%s", m.Host, m.ContainerPort, strings.ToLower(string(m.Protocol)))))
	}
	return lines(out...)
}

func composeText(cs doctor.ComposeService) string {
	if cs.Service == "" {
		return cs.Project
	}
	return cs.Project + " / " + cs.Service
}

func pidText(occ doctor.Occupant) string {
	if occ.Process.PID == 0 {
		return dimStyle.Render("unknown")
	}
	return fmt.Sprint(occ.Process.PID)
}

func nameText(occ doctor.Occupant) string {
	switch {
	case occ.Exited:
		return dimStyle.Render("unavailable (process exited)")
	case occ.Process.Name == "":
		return unavailable()
	default:
		return occ.Process.Name
	}
}

func unavailable() string {
	return dimStyle.Render("unavailable")
}

func suggestions(ss []doctor.Suggestion) string {
	if len(ss) == 0 {
		return ""
	}
	out := []string{headingStyle.Render("Suggestions")}
	for i, s := range ss {
		if i > 0 {
			out = append(out, "")
		}
		out = append(out, "  "+s.Title+":")
		for _, c := range s.Commands {
			out = append(out, "    "+commandStyle.Render(c))
		}
	}
	return lines(out...)
}

// field aligns a label and its value; labels are padded to the width of the
// widest one ("Protocol") plus two spaces.
func field(label, value string) string {
	return fmt.Sprintf("  %-10s%s", label, value)
}

func lines(ls ...string) string {
	return strings.Join(ls, "\n")
}

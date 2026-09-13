// Package presenter renders a port-doctor report for humans in a terminal.
package presenter

import (
	"cmp"
	"fmt"
	"io"
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
		if r.Diagnosis != "" {
			sections = append(sections, lines(headingStyle.Render("Diagnosis"), "  "+r.Diagnosis))
		}
		if s := suggestions(r.Suggestions); s != "" {
			sections = append(sections, s)
		}
	}
	if len(r.Notes) > 0 {
		notes := make([]string, 0, len(r.Notes))
		for _, n := range r.Notes {
			notes = append(notes, dimStyle.Render(n))
		}
		sections = append(sections, lines(notes...))
	}

	_, err := lipgloss.Fprint(w, strings.Join(sections, "\n\n")+"\n")
	return err
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

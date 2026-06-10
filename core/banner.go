package core

import (
	"fmt"
	"strings"

	"github.com/fatih/color"
)

const (
	VERSION = "4.0.0."
)

func putAsciiArt(s string) {
	for _, c := range s {
		d := string(c)
		switch string(c) {
		case "M", "A", "V", "Y", "H", "d", "m", "a", "o", "v": // Main mane & body
			color.Set(color.FgHiRed) // Golden lion mane + body
		case "~", "_", "-": // Waves, accents, details
			color.Set(color.FgRed)
		case "`", "'": // Small details, eyes, whiskers
			color.Set(color.FgHiWhite)
		case "*", " ": // Background / empty
			color.Unset()
		default:
			color.Set(color.FgHiRed) // Fallback: everything else = lion color
		}
		fmt.Print(d)
	}
	color.Unset()
}

func printLogo(s string) {
	for _, c := range s {
		d := string(c)
		switch string(c) {
		case "_":
			color.Set(color.FgWhite)
		case "\n":
			color.Unset()
		default:
			color.Set(color.FgHiBlack)
		}
		fmt.Print(d)
	}
	color.Unset()
}

func printUpdateName() {
	nameClr := color.New(color.FgHiWhite)
	txt := nameClr.Sprintf("	+++++++++++[ELITE REDTEAM CCXIV]+++++++++++")
	fmt.Fprintf(color.Output, "%s", txt)
}

func printOneliner1() {
	handleClr := color.New(color.FgHiRed)
	versionClr := color.New(color.FgGreen)
	textClr := color.New(color.FgHiBlack)
	spc := strings.Repeat(" ", 8-len(VERSION))
	txt := textClr.Sprintf("       PROPERTY OF: ") + handleClr.Sprintf("(THE COMMISION)") + spc + textClr.Sprintf("VERSION: ") + versionClr.Sprintf("%s", VERSION)
	fmt.Fprintf(color.Output, "%s", txt)
}

func printOneliner2() {
	textClr := color.New(color.FgHiBlack)
	red := color.New(color.FgRed)
	white := color.New(color.FgWhite)
	txt := red.Sprintf("       OPERATION (ELITE REDTEAM CCXIV)") + white.Sprintf(" - ") + textClr.Sprintf("SYNDICATES")
	fmt.Fprintf(color.Output, "%s", txt)
}

func Banner() {
	fmt.Println()

	// Beautiful golden lion that actually looks like a lion now
	putAsciiArt(`
		░█▀▄░█▀▀░█▀▄░▀█▀░█▀▀░█▀█░█▄█
		░█▀▄░█▀▀░█░█░░█░░█▀▀░█▀█░█░█
		░▀░▀░▀▀▀░▀▀░░░▀░░▀▀▀░▀░▀░▀░▀                                                       
`)
	printUpdateName()
	fmt.Println()
	printOneliner1()
	fmt.Println()
	printOneliner2()
	fmt.Println()
}
package e2e

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/cucumber/godog"

	"github.com/henry40408/comics/e2e/internal/harness"
)

func registerLibrarySteps(sc *godog.ScenarioContext, w *world) {
	sc.Step(`^I open the library$`, w.openTheLibrary)
	sc.Step(`^I should see (\d+) books$`, w.shouldSeeBooks)
	sc.Step(`^I open the first book$`, w.openTheFirstBook)
	sc.Step(`^I should be in the reader$`, w.shouldBeInTheReader)
	sc.Step(`^the library should list `+quoted+` with `+quoted+`$`, w.libraryLists)
	sc.Step(`^the cards should be numbered `+quoted+`$`, w.cardsNumbered)
	sc.Step(`^the library should report (\d+) volumes$`, w.libraryReportsVolumes)
	sc.Step(`^the scan times should be shown$`, w.scanTimesShown)
	sc.Step(`^the page title should start with `+quoted+`$`, w.titleStartsWith)
	sc.Step(`^I shuffle from the library$`, w.shuffleFromLibrary)
	sc.Step(`^I re-scan the library$`, w.rescanLibrary)
	sc.Step(`^I toggle the theme$`, w.toggleTheme)
}

func (w *world) openTheLibrary() error {
	return w.browser.Library().Goto()
}

func (w *world) shouldSeeBooks(count string) error {
	expected, err := strconv.Atoi(count)
	if err != nil {
		return err
	}
	return harness.EventuallyEq("book count", expected, func() (int, error) {
		cards, err := w.browser.Library().Cards()
		return len(cards), err
	})
}

func (w *world) openTheFirstBook() error {
	return w.browser.Library().OpenFirstBook()
}

// shouldBeInTheReader needs no wait on the URL: OpenFirstBook already
// confirmed the path.
func (w *world) shouldBeInTheReader() error {
	return harness.Eventually("the reader body is showing", w.browser.Reader().IsShowing)
}

func (w *world) libraryLists(title, pages string) error {
	cards, err := w.browser.Library().CardSummaries()
	if err != nil {
		return err
	}
	title, pages = unquote(title), unquote(pages)
	index := slices.IndexFunc(cards, func(card harness.CardSummary) bool { return card.Title == title })
	if index < 0 {
		return fmt.Errorf("no card titled %q among %+v", title, cards)
	}
	card := cards[index]
	if card.Pages != pages {
		return fmt.Errorf("%q shows %q", title, card.Pages)
	}
	if card.CoverAlt != title {
		return fmt.Errorf("%q has cover alt %q", title, card.CoverAlt)
	}
	return nil
}

func (w *world) cardsNumbered(expected string) error {
	cards, err := w.browser.Library().CardSummaries()
	if err != nil {
		return err
	}
	indexes := make([]string, 0, len(cards))
	for _, card := range cards {
		indexes = append(indexes, card.Index)
	}
	if strings.Join(indexes, ", ") != unquote(expected) {
		return fmt.Errorf("numbered %q", indexes)
	}
	return nil
}

func (w *world) libraryReportsVolumes(count string) error {
	header, note, err := w.browser.Library().VolumeCounts()
	if err != nil {
		return err
	}
	if header != count {
		return fmt.Errorf("header says %q", header)
	}
	if !strings.Contains(note, count) {
		return fmt.Errorf("note says %q", note)
	}
	return nil
}

func (w *world) scanTimesShown() error {
	times, err := w.browser.Library().ScanTimes()
	if err != nil {
		return err
	}
	if len(times) != 2 {
		return fmt.Errorf("expected two <time> elements: %q", times)
	}
	if slices.ContainsFunc(times, func(text string) bool { return strings.TrimSpace(text) == "" }) {
		return fmt.Errorf("blank: %q", times)
	}
	if !strings.HasSuffix(times[1], "ms") {
		return fmt.Errorf("duration reads %q", times[1])
	}
	return nil
}

func (w *world) titleStartsWith(prefix string) error {
	title, err := w.browser.Title()
	if err != nil {
		return err
	}
	if !strings.HasPrefix(title, unquote(prefix)) {
		return fmt.Errorf("title is %q", title)
	}
	return nil
}

func (w *world) shuffleFromLibrary() error {
	return w.browser.Library().Shuffle()
}

func (w *world) rescanLibrary() error {
	return w.browser.Library().Rescan()
}

func (w *world) toggleTheme() error {
	before, err := w.browser.Theme()
	if err != nil {
		return err
	}
	return w.browser.ClickThemeToggle(before)
}

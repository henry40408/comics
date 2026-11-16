package e2e

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/cucumber/godog"

	"github.com/henry40408/comics/e2e/internal/harness"
)

func registerReaderSteps(sc *godog.ScenarioContext, w *world) {
	sc.Step(`^I am reading the first book$`, w.readingTheFirstBook)
	sc.Step(`^the current page should be `+quoted+`$`, w.currentPageShouldBe)
	sc.Step(`^the `+quoted+` arrow should be `+quoted+`$`, w.arrowShouldBe)
	sc.Step(`^I advance to the next page$`, w.advance)
	sc.Step(`^I go back to the previous page$`, w.goBack)
	sc.Step(`^I switch to scroll mode$`, w.switchToScrollMode)
	sc.Step(`^the reader should be in `+quoted+` mode$`, w.readerShouldBeInMode)
	sc.Step(`^page `+quoted+` should be the only one showing$`, w.onlyPageShowing)
	sc.Step(`^I follow the next-page link$`, w.followNext)
	sc.Step(`^I follow the previous-page link$`, w.followPrevious)
	sc.Step(`^the shared mode control should not be visible$`, w.sharedModeControlHidden)
	sc.Step(`^I switch mode from page `+quoted+`$`, w.switchModeFromPage)
	sc.Step(`^page `+quoted+` should be in view$`, w.pageShouldBeInView)
	sc.Step(`^the theme toggle should not be visible$`, w.themeToggleHidden)
	sc.Step(`^the top bar should not show the current page$`, w.topbarPageNumberHidden)
	sc.Step(`^the top bar should still read `+quoted+`$`, w.topbarShouldRead)
	sc.Step(`^all `+quoted+` pages should be showing$`, w.allPagesShowing)
	sc.Step(`^I jump to page `+quoted+` from the rail$`, w.jumpFromRail)
	sc.Step(`^the page counter should read `+quoted+`$`, w.counterShouldRead)
	sc.Step(`^the reader should have remembered the first-visit hint$`, w.hintRemembered)
	sc.Step(`^the progress bar should be `+quoted+` wide$`, w.progressWidth)
	sc.Step(`^I follow the back link$`, w.followBackLink)
	sc.Step(`^I shuffle from the reader$`, w.shuffleFromReader)
	sc.Step(`^the reader title should be `+quoted+`$`, w.readerTitle)
	sc.Step(`^I reload the reader in `+quoted+` mode$`, w.reloadReaderInMode)
	sc.Step(`^the segmented control should highlight `+quoted+`$`, w.segmentedControlHighlights)
	sc.Step(`^page `+quoted+` should offer no previous-page link$`, w.noPreviousLink)
	sc.Step(`^page `+quoted+` should offer no next-page link$`, w.noNextLink)
}

// readerOf is the scenario's reader page object.
func (w *world) readerOf() (harness.ReaderPage, error) {
	b, err := w.browserOf()
	if err != nil {
		return harness.ReaderPage{}, err
	}
	return b.Reader(), nil
}

func (w *world) readingTheFirstBook() error {
	b, err := w.browserOf()
	if err != nil {
		return err
	}
	library := b.Library()
	if err := library.Goto(); err != nil {
		return err
	}
	if err := library.OpenFirstBook(); err != nil {
		return err
	}
	return harness.Eventually("url is a book", func() (bool, error) {
		path, err := b.Path()
		return strings.HasPrefix(path, "/book/"), err
	})
}

func (w *world) currentPageShouldBe(n string) error {
	reader, err := w.readerOf()
	if err != nil {
		return err
	}
	return harness.EventuallyEq("the topbar page number", unquote(n), func() (string, error) {
		text, err := reader.CurrentPageText()
		if text == nil {
			return "", err
		}
		return *text, err
	})
}

func (w *world) arrowShouldBe(direction, state string) error {
	reader, err := w.readerOf()
	if err != nil {
		return err
	}
	return harness.EventuallyEq("the tap-zone arrow", unquote(state) == "shown", func() (bool, error) {
		return reader.ArrowShown(unquote(direction))
	})
}

func (w *world) advance() error {
	reader, err := w.readerOf()
	if err != nil {
		return err
	}
	return reader.Advance()
}

func (w *world) goBack() error {
	reader, err := w.readerOf()
	if err != nil {
		return err
	}
	return reader.GoBack()
}

func (w *world) switchToScrollMode() error {
	reader, err := w.readerOf()
	if err != nil {
		return err
	}
	return reader.SetScrollMode()
}

func (w *world) readerShouldBeInMode(mode string) error {
	reader, err := w.readerOf()
	if err != nil {
		return err
	}
	return harness.EventuallyEq("the reader mode", unquote(mode), reader.Mode)
}

func (w *world) onlyPageShowing(n string) error {
	reader, err := w.readerOf()
	if err != nil {
		return err
	}
	err = harness.Eventually("exactly one page is showing", func() (bool, error) {
		pages, err := reader.VisiblePages()
		return len(pages) == 1, err
	})
	if err != nil {
		return err
	}
	return harness.EventuallyEq("the showing page", "p"+unquote(n), func() (string, error) {
		ids, err := reader.DisplayedPageIDs()
		if len(ids) == 0 {
			return "", err
		}
		return ids[0], err
	})
}

func (w *world) followNext() error {
	reader, err := w.readerOf()
	if err != nil {
		return err
	}
	return reader.FollowNext()
}

func (w *world) followPrevious() error {
	reader, err := w.readerOf()
	if err != nil {
		return err
	}
	return reader.FollowPrevious()
}

func (w *world) sharedModeControlHidden() error {
	reader, err := w.readerOf()
	if err != nil {
		return err
	}
	control, err := reader.SharedModeControl()
	if err != nil {
		return err
	}
	return assertHidden("the shared mode control", control)
}

func (w *world) switchModeFromPage(n string) error {
	reader, err := w.readerOf()
	if err != nil {
		return err
	}
	return reader.SwitchModeFrom(unquote(n))
}

func (w *world) pageShouldBeInView(n string) error {
	b, err := w.browserOf()
	if err != nil {
		return err
	}
	number := unquote(n)
	// In scroll mode every page is displayed, so only the viewport says where
	// the browser landed.
	return harness.Eventually(fmt.Sprintf("page %s is in the viewport", number), func() (bool, error) {
		return b.IsInViewport("p" + number)
	})
}

func (w *world) themeToggleHidden() error {
	reader, err := w.readerOf()
	if err != nil {
		return err
	}
	toggle, err := reader.ThemeToggle()
	if err != nil {
		return err
	}
	return assertHidden("the theme toggle", toggle)
}

func (w *world) topbarPageNumberHidden() error {
	reader, err := w.readerOf()
	if err != nil {
		return err
	}
	current, err := reader.CurrentPage()
	if err != nil {
		return err
	}
	return assertHidden("the topbar page number", current)
}

func (w *world) topbarShouldRead(text string) error {
	reader, err := w.readerOf()
	if err != nil {
		return err
	}
	// Rendered text, not textContent, which keeps a hidden span's characters.
	return harness.EventuallyEq("the topbar subtitle", unquote(text), reader.TopbarSubtitle)
}

func (w *world) allPagesShowing(n string) error {
	reader, err := w.readerOf()
	if err != nil {
		return err
	}
	expected, err := strconv.Atoi(unquote(n))
	if err != nil {
		return err
	}
	return harness.EventuallyEq("the number of showing pages", expected, func() (int, error) {
		pages, err := reader.VisiblePages()
		return len(pages), err
	})
}

func (w *world) jumpFromRail(n string) error {
	reader, err := w.readerOf()
	if err != nil {
		return err
	}
	return reader.JumpFromRail(unquote(n))
}

func (w *world) counterShouldRead(text string) error {
	reader, err := w.readerOf()
	if err != nil {
		return err
	}
	return harness.EventuallyEq("the page counter", unquote(text), reader.CounterText)
}

func (w *world) hintRemembered() error {
	reader, err := w.readerOf()
	if err != nil {
		return err
	}
	flag, err := reader.FirstVisitHint()
	if err != nil {
		return err
	}
	if flag != "1" {
		return fmt.Errorf("flag is %q", flag)
	}
	return nil
}

func (w *world) progressWidth(width string) error {
	reader, err := w.readerOf()
	if err != nil {
		return err
	}
	return harness.EventuallyEq("the progress bar width", unquote(width), reader.ProgressWidth)
}

func (w *world) followBackLink() error {
	reader, err := w.readerOf()
	if err != nil {
		return err
	}
	return reader.GoHome()
}

func (w *world) shuffleFromReader() error {
	reader, err := w.readerOf()
	if err != nil {
		return err
	}
	return reader.Shuffle()
}

func (w *world) readerTitle(title string) error {
	reader, err := w.readerOf()
	if err != nil {
		return err
	}
	return harness.EventuallyEq("the reader title", unquote(title), reader.Title)
}

func (w *world) reloadReaderInMode(mode string) error {
	reader, err := w.readerOf()
	if err != nil {
		return err
	}
	return reader.ReloadInMode(unquote(mode))
}

func (w *world) segmentedControlHighlights(mode string) error {
	reader, err := w.readerOf()
	if err != nil {
		return err
	}
	highlighted, err := reader.HighlightedMode()
	if err != nil {
		return err
	}
	if highlighted != unquote(mode) {
		return fmt.Errorf("highlights %q", highlighted)
	}
	return nil
}

func (w *world) noPreviousLink(n string) error {
	return w.pageHasNo(unquote(n), ".nojs-prev")
}

func (w *world) noNextLink(n string) error {
	return w.pageHasNo(unquote(n), ".nojs-next")
}

func (w *world) pageHasNo(n, selector string) error {
	reader, err := w.readerOf()
	if err != nil {
		return err
	}
	page, err := reader.Page(n)
	if err != nil {
		return err
	}
	found, err := page.FindAll(selector)
	if err != nil {
		return err
	}
	if len(found) > 0 {
		return fmt.Errorf("page %s carries `%s`", n, selector)
	}
	return nil
}

// assertHidden fails if the element is displayed; absent counts as hidden.
func assertHidden(what string, element *harness.Element) error {
	if element == nil {
		return nil
	}
	shown, err := element.Displayed()
	if err != nil {
		return err
	}
	if shown {
		return fmt.Errorf("%s is showing, but nothing should offer it without a script", what)
	}
	return nil
}

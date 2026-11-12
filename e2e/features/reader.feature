Feature: Reader

  Background:
    Given I am logged in
    And I am reading the first book

  Scenario: The reader opens on the first page
    Then the current page should be "1"

  Scenario: Advancing turns to the next page
    When I advance to the next page
    Then the current page should be "2"

  Scenario: Switching to scroll mode
    When I switch to scroll mode
    Then the reader should be in "scroll" mode

  # The thumbnails are anchors; app.js cancels the navigation and animates.
  Scenario: Jumping from the thumbnail rail
    When I jump to page "3" from the rail
    Then the current page should be "3"

  Scenario: Going back to the previous page
    When I advance to the next page
    And I go back to the previous page
    Then the current page should be "1"

  # The page order is right to left, so the left arrow is "next".
  Scenario: The arrow keys turn pages right to left
    When I press "ArrowLeft"
    Then the current page should be "2"
    When I press "ArrowRight"
    Then the current page should be "1"

  Scenario: Space turns to the next page
    When I press "Space"
    Then the current page should be "2"

  Scenario: Home and End jump to the first and last page
    When I press "End"
    Then the current page should be "3"
    And the progress bar should be "100%" wide
    When I press "Home"
    Then the current page should be "1"

  Scenario: The m key toggles the mode
    When I press "m"
    Then the reader should be in "scroll" mode
    When I press "m"
    Then the reader should be in "paged" mode

  Scenario: The t key toggles the theme
    Given the system prefers the "light" colour scheme
    When I reload the page
    Then the theme should be "light"
    When I press "t"
    Then the theme should be "dark"

  # The `m` key, not a click: a focused link makes app.js ignore the keyboard.
  Scenario: Scrolling tracks the page in view
    When I press "m"
    And I press "End"
    Then the current page should be "3"

  # The class lasts 2s, too short to assert on a slow runner; the stored flag
  # is what shows the hint ran, and what keeps it to the first visit.
  Scenario: The first visit hints at the tap zones
    Then the reader should have remembered the first-visit hint

  Scenario: The back link returns to the library
    When I follow the back link
    Then I should see the library

  Scenario: Shuffle opens the other book
    When I shuffle from the reader
    Then the reader title should be "Pepper and Carrot 02 - Rainbow Potions"

  Scenario: Every image and asset the reader links is served
    Then every image and asset on the page should be served
    And the page should show images
    And the page should have no inline script or style

  # Server-rendered, so it holds without a script as well.
  @nojs
  Scenario: A link can open the reader in scroll mode
    When I reload the reader in "scroll" mode
    Then the reader should be in "scroll" mode
    And the segmented control should highlight "scroll"
    And all "3" pages should be showing

  @nojs
  Scenario: The first page offers no previous link and the last no next link
    Then page "1" should offer no previous-page link
    When I follow the next-page link
    And I follow the next-page link
    Then page "3" should offer no next-page link

  # `@nojs` runs with scripting off; paging falls back to per-page anchors
  # resolved by CSS `:target`.
  @nojs
  Scenario: Paging works without JavaScript
    Then page "1" should be the only one showing
    When I follow the next-page link
    Then page "2" should be the only one showing
    When I follow the next-page link
    Then page "3" should be the only one showing
    When I follow the previous-page link
    Then page "2" should be the only one showing

  @nojs
  Scenario: Controls that need a script are not offered without one
    Then the theme toggle should not be visible
    And the top bar should not show the current page
    And the top bar should still read "3 ページ"

  # Without a script the switch lives on each page: the shared one would drop
  # you at page 1.
  @nojs
  Scenario: Switching to scroll mode works without JavaScript
    Then the shared mode control should not be visible
    When I switch mode from page "1"
    Then the reader should be in "scroll" mode
    And all "3" pages should be showing

  @nojs
  Scenario: Switching mode keeps your place without JavaScript
    When I follow the next-page link
    And I follow the next-page link
    Then page "3" should be the only one showing
    When I switch mode from page "3"
    Then the reader should be in "scroll" mode
    And page "3" should be in view
    When I switch mode from page "3"
    Then the reader should be in "paged" mode
    And page "3" should be the only one showing

  @nojs
  Scenario: The rail and the page counter work without JavaScript
    Then the page counter should read "1 / 3"
    When I jump to page "3" from the rail
    Then page "3" should be the only one showing
    And the page counter should read "3 / 3"

  # Runs in the exclusive pass, after every other scenario: logging out ends
  # *every* session.
  @logout
  Scenario: Logging out returns to the login page
    When I log out
    Then I should be on the login page

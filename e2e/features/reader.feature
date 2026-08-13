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

  # The thumbnails are anchors now, so app.js has to cancel the navigation and
  # animate instead — this covers that the scripted path still works.
  Scenario: Jumping from the thumbnail rail
    When I jump to page "3" from the rail
    Then the current page should be "3"

  # Runs in the `e2e-nojs` project, which serves the same pages with scripting
  # off. Paging falls back to per-page anchors resolved by CSS `:target`.
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

  @nojs
  Scenario: Switching to scroll mode works without JavaScript
    When I switch to scroll mode
    Then the reader should be in "scroll" mode
    And all "3" pages should be showing

  @nojs
  Scenario: The rail and the page counter work without JavaScript
    Then the page counter should read "1 / 3"
    When I jump to page "3" from the rail
    Then page "3" should be the only one showing
    And the page counter should read "3 / 3"

  Scenario: Logging out returns to the login page
    When I log out
    Then I should be on the login page

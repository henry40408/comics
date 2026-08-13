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

  Scenario: Logging out returns to the login page
    When I log out
    Then I should be on the login page

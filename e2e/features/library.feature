Feature: Library

  Background:
    Given I am logged in

  Scenario: The library lists the seeded books
    When I open the library
    Then I should see 2 books

  Scenario: Opening a book enters the reader
    When I open the library
    And I open the first book
    Then I should be in the reader

  Scenario: Each card shows its book's title, page count and number
    When I open the library
    Then the library should list "Pepper and Carrot 01 - Potion of Flight" with "3 pages"
    And the library should list "Pepper and Carrot 02 - Rainbow Potions" with "5 pages"
    And the cards should be numbered "1, 2"

  Scenario: The header summarises the scan
    When I open the library
    Then the library should report 2 volumes
    And the scan times should be shown
    And the page title should start with "2 book(s) | Comics"

  Scenario: Every image and asset the library links is served
    When I open the library
    Then every image and asset on the page should be served
    And the page should show images
    And the page should have no inline script or style

  Scenario: Shuffle opens a book
    When I open the library
    And I shuffle from the library
    Then I should be in the reader

  Scenario: The theme toggle flips the theme and remembers it
    Given the system prefers the "light" colour scheme
    When I open the library
    Then the theme should be "light"
    When I toggle the theme
    Then the theme should be "dark"
    When I reload the page
    Then the theme should be "dark"

  # Runs in the exclusive pass: logging out ends *every* session.
  @logout
  Scenario: Logging out from the library returns to the login page
    When I open the library
    And I log out
    Then I should be on the login page

  # Runs in the exclusive pass: a rescan swaps the scan every other
  # scenario reads.
  @rescan
  Scenario: Re-scan returns to the library with every book
    When I open the library
    And I re-scan the library
    Then I should see the library
    And I should see 2 books

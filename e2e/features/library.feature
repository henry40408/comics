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

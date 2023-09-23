Feature: Watch comic books

  Background:
    Given a comics server

  Scenario: User visits the front page
    When the user visits the front page
    Then they should see comic books

  Scenario: User visits a comic book
    When the user visits a comic book
    Then they should see pages of the comic book

  Scenario: User shuffles comic books
    When the user shuffles comic books
    Then they should be redirected to a random book

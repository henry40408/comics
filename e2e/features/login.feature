Feature: Login

  Scenario: Signing in with valid credentials reaches the library
    Given I am on the login page
    When I sign in with username "user" and password "password"
    Then I should see the library

  Scenario: Signing in with a wrong password shows an error
    Given I am on the login page
    When I sign in with username "user" and password "wrong"
    Then I should see the login error
    And I should be on the login page

  Scenario: The username field is focused on arrival
    Given I am on the login page
    Then the username field should be focused

  Scenario: A protected page sends you to the login page and back
    When I visit "/?from=e2e"
    Then I should be on the login page
    And the login form should remember "/?from=e2e"
    When I sign in with username "user" and password "password"
    Then I should be at "/?from=e2e"

  Scenario: An off-site redirect target is refused
    When I visit "/login?next=//evil.example/x"
    Then the login form should remember "/"

  Scenario: The redirect target is escaped in the page
    When I visit "/login?next=%2F%22%3E%3Cb%20id%3D%22injected%22%3E"
    Then the login form should remember '/"><b id="injected">'
    And the page should have no element "#injected"

  Scenario: Every image and asset the login page links is served
    When I visit "/login"
    Then every image and asset on the page should be served
    And the page should have no inline script or style

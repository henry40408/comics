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

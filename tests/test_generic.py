#!/usr/bin/env python3

import pytest
import re
from playwright.sync_api import Page, expect


@pytest.fixture(scope="function", autouse=True)
def before_each_after_each(page: Page):

    print("before the test runs")

    # Go to the starting url before each test.
    page.goto("http://127.0.0.1:5100/index")
    yield

    print("after the test runs")


def test_has_title(page: Page) -> None:
    # Expect a title "to contain" a substring.
    expect(page).to_have_title(re.compile("Lookyloo"))


def test_get_started_link(page: Page) -> None:
    page.get_by_role("link", name="Start a new capture").click()
    page.get_by_role("button", name="Lacus Selection").click()
    expect(page.get_by_role("button", name="Browser Configuration")).to_be_visible()

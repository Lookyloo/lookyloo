#!/usr/bin/env python3

import pytest
import re
import time

from collections.abc import Generator

from playwright.sync_api import Page, expect


@pytest.fixture(scope="function", autouse=True)
def before_each_after_each(page: Page) -> Generator[None, None, None]:

    print("before the test runs")

    # Go to the starting url before each test.
    page.goto("http://127.0.0.1:5100/index")
    yield

    print("after the test runs")


def test_has_title(page: Page) -> None:
    # Expect a title "to contain" a substring.
    expect(page).to_have_title(re.compile("Lookyloo"))


def test_capture_page(page: Page) -> None:
    page.get_by_role("link", name="Start a new capture").click()
    page.get_by_role("button", name="Lacus Selection").click()
    expect(page.get_by_role("button", name="Browser Configuration")).to_be_visible()
    page.get_by_role("textbox", name="URL to capture").click()
    page.get_by_role("textbox", name="URL to capture").fill("https://google.fr")
    page.get_by_role("button", name="Start looking!").click()
    # Capture ongoing
    expect(page).to_have_title(re.compile("Ongoing capture..."), timeout=10)
    max_loop = 5
    while max_loop > 0:
        # Wait for the capture to be done
        try:
            expect(page).to_have_title(re.compile("Ongoing capture..."))
            time.sleep(10)
            max_loop -= 1
        except AssertionError:
            break
    # Capture done
    expect(page).to_have_title(re.compile("Capture of https://google.fr"))
    expect(page.get_by_text("The capture has not been")).to_be_visible()
    # trigger indexing
    page.get_by_role("button", name="Analytical Tools").click()
    page.get_by_role("button", name="Index capture").click()
    page.get_by_role("button", name="Analytical Tools").click()
    expect(page.get_by_role("button", name="Index capture")).to_have_count(0)
    # go to search page and search
    page.get_by_role("link", name="Lookyloo icon").click()
    page.get_by_role("button", name="Toggle navigation").click()
    page.get_by_role("link", name="Search").click()
    expect(page).to_have_title(re.compile("Search"))
    page.get_by_role("textbox", name="URL part:").fill("google.fr")
    page.get_by_role("button", name="Search").click()
    expect(page).to_have_title(re.compile("google.fr"))
    expect(page.get_by_text("Google The capture contains").first).to_be_visible()

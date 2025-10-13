#!/usr/bin/env python3

import re
from playwright.sync_api import Page, expect


def test_has_title(page: Page):
    page.goto("http://127.0.0.1:5100/index")

    # Expect a title "to contain" a substring.
    expect(page).to_have_title(re.compile("Lookyloo"))


def test_get_started_link(page: Page):
    page.goto("http://127.0.0.1:5100/index")

    page.get_by_role("link", name="Start a new capture").click()
    expect(page.get_by_role("button", name="Browser Configuration")).to_be_visible()

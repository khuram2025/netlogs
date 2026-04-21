"""
HTML → PDF rendering for analytics reports.

Uses a headless Chromium via Playwright so we can author the report as
a Jinja2 HTML/CSS template (same skill set as the rest of the web UI)
instead of a separate PDF DSL. Chrome handles all of CSS, web fonts,
page breaks, headers/footers, and print backgrounds correctly.

The module is deliberately thin: one entry point, ``render_html_to_pdf``,
takes a fully-rendered HTML string and returns PDF bytes. Everything
above it (data assembly, template rendering) lives in the view layer.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Optional

logger = logging.getLogger(__name__)


async def render_html_to_pdf(
    html: str,
    *,
    header_html: Optional[str] = None,
    footer_html: Optional[str] = None,
    paper_format: str = "A4",
) -> bytes:
    """Render ``html`` to a PDF and return the bytes.

    A fresh Chromium instance is launched per call (~0.5–1s overhead on
    this host). Reports are small enough that a browser pool isn't worth
    the lifecycle complexity for the MVP; if we ever see > ~100 reports/min
    we'll want to hold a long-lived context open.

    Page setup:
      - A4 portrait, 15mm margins.
      - ``print_background=True`` so CSS backgrounds (KPI tiles, band
        colours, header strips) actually appear in the PDF.
      - Optional header/footer HTML slotted into Chromium's template
        variables (``<span class="pageNumber"></span>`` etc.).
    """
    # Import here so the service module can still be imported in tests
    # that don't exercise PDF rendering (Playwright is heavyweight).
    from playwright.async_api import async_playwright

    async with async_playwright() as p:
        browser = await p.chromium.launch(args=["--no-sandbox"])
        try:
            page = await browser.new_page()
            # ``wait_until='networkidle'`` would block forever on our
            # fully-inline templates because nothing loads; ``load`` is
            # the right signal — the DOM is ready as soon as set_content
            # returns.
            await page.set_content(html, wait_until="load")
            # Give CSS @font-face / custom fonts one frame to settle.
            await page.evaluate("document.fonts && document.fonts.ready")
            pdf_kwargs = {
                "format": paper_format,
                "print_background": True,
                "prefer_css_page_size": True,
                "margin": {
                    "top": "18mm", "bottom": "18mm",
                    "left": "15mm", "right": "15mm",
                },
            }
            if header_html or footer_html:
                pdf_kwargs["display_header_footer"] = True
                # Chromium requires non-empty strings — use a zero-width
                # span if the caller only wanted the other half.
                pdf_kwargs["header_template"] = header_html or "<span></span>"
                pdf_kwargs["footer_template"] = footer_html or "<span></span>"
            return await page.pdf(**pdf_kwargs)
        finally:
            await browser.close()


def render_html_to_pdf_sync(html: str, **kwargs) -> bytes:
    """Convenience wrapper for code paths that are already synchronous.

    Not to be called from inside the FastAPI request loop — use the async
    ``render_html_to_pdf`` there to avoid blocking the worker.
    """
    return asyncio.run(render_html_to_pdf(html, **kwargs))

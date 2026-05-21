import asyncio
from playwright.async_api import async_playwright
import sys

async def main(program_name):
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()

        print(f"Connecting to BountyScope to fetch LLM Data for: {program_name}")
        await page.goto("http://10.147.19.100:8505/")
        await page.wait_for_load_state("networkidle")

        # 1. Navigate to AI / RAG Context tab in sidebar
        print("Navigating to 'AI / RAG Context' tab...")
        try:
            # Use a more specific locator to avoid strict mode violation
            # The tab is likely an 'stVerticalNavigationElement' or similar
            await page.get_by_role("tab", name="AI / RAG Context").click()
            await page.wait_for_timeout(3000)
        except Exception as e:
            print(f"Could not find AI / RAG Context tab: {e}")
            # Try fallback to selecting by text but picking the first one
            try:
                await page.get_by_text("AI / RAG Context").first.click()
                await page.wait_for_timeout(3000)
            except:
                await browser.close()
                return

        # 2. Select program on the RAG page
        print(f"Selecting program '{program_name}' on RAG page...")
        try:
            # Find the selectbox specifically for program selection
            # It usually has a label 'Select Program for Context'
            await page.get_by_label("Select Program for Context").click()
            await page.wait_for_timeout(1000)
            await page.keyboard.type(program_name)
            await page.wait_for_timeout(1000)
            await page.keyboard.press("Enter")
            await page.wait_for_timeout(5000)
        except Exception as e:
            print(f"Failed to select program with label: {e}")
            # Fallback to first selectbox
            try:
                await page.locator('div[data-testid="stSelectbox"]').first.click()
                await page.keyboard.type(program_name)
                await page.keyboard.press("Enter")
                await page.wait_for_timeout(5000)
            except:
                pass

        # 3. Try to click 'Generate Master RAG JSON' and download
        print("Clicking 'Generate Master RAG JSON' and capturing download...")
        try:
            await page.get_by_role("button", name="Generate Master RAG JSON").click()
            await page.wait_for_timeout(3000)
            
            # Now look for the download button
            async with page.expect_download(timeout=10000) as download_info:
                await page.get_by_text("Download Nested JSON for LLM/RAG").click()
            
            download = await download_info.value
            path = f"/tmp/{program_name.replace(' ', '_')}_rag.json"
            await download.save_as(path)
            print(f"Successfully captured JSON export to {path}")
            
            with open(path, "r") as f:
                content = f.read()
                # Print a snippet of the JSON to verify
                print(f"\n--- LLM INGESTIBLE JSON (Snippet) ---\n{content[:2000]}...\n--- END SNIPPET ---\n")
            
            await browser.close()
            return
        except Exception as e:
            print(f"JSON generation or download failed: {e}")

        # 4. Extract LLM Context Chunk
        print("Extracting LLM Context...")
        try:
            # Look for a code block or text area containing the context
            # In Streamlit, this might be st.code or st.text_area
            context_area = page.locator('div[data-testid="stCodeBlock"] pre, div[data-testid="stMarkdown"] pre')
            if await context_area.count() > 0:
                content = await context_area.first.inner_text()
                print(f"\n--- LLM INGESTIBLE CONTEXT START ---\n{content}\n--- LLM INGESTIBLE CONTEXT END ---\n")
            else:
                # Try getting all text if no code block found
                all_text = await page.evaluate("() => document.body.innerText")
                if "LLM Context Chunk" in all_text:
                    # Extract the part after LLM Context Chunk
                    parts = all_text.split("LLM Context Chunk")
                    if len(parts) > 1:
                        print(f"\n--- LLM INGESTIBLE CONTEXT START ---\n{parts[1].strip()}\n--- LLM INGESTIBLE CONTEXT END ---\n")
                    else:
                        print("Context found but could not be parsed.")
                else:
                    print("Could not find LLM Context Chunk on page.")
        except Exception as e:
            print(f"Extraction failed: {e}")

        await browser.close()


if __name__ == "__main__":
    prog = sys.argv[1] if len(sys.argv) > 1 else "Tripadvisor"
    asyncio.run(main(prog))

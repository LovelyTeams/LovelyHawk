// What a keyboard or screen-reader user meets on the page as it stands: every
// visible control has a name, every image a text alternative, ids are unique,
// and the page says what it is with a heading. Hidden controls are skipped —
// they are not reachable, and naming them is not the page's job yet.
//
// An expression for CDP Runtime.evaluate, shared by the desktop smoke and its
// negative self-test, so the check that passes is the one shown to fail.
export const ACCESSIBILITY_AUDIT = `(() => {
  const visible = (element) => {
    const box = element.getBoundingClientRect();
    const style = getComputedStyle(element);
    return box.width > 0 && box.height > 0 && style.visibility !== "hidden" && style.display !== "none";
  };
  const nameOf = (element) => {
    const labelled = element.getAttribute("aria-labelledby");
    const byId = labelled === null ? "" : labelled.split(/\\s+/u).map((id) => document.getElementById(id)?.textContent ?? "").join(" ");
    const labels = "labels" in element && element.labels ? [...element.labels].map((label) => label.textContent).join(" ") : "";
    // A field's options or typed value are not its name.
    const field = ["SELECT", "TEXTAREA"].includes(element.tagName) ||
      (element.tagName === "INPUT" && !["button", "submit", "reset"].includes(element.type));
    return [element.getAttribute("aria-label"), byId, labels, element.getAttribute("title"),
      element.tagName === "INPUT" && ["button", "submit", "reset"].includes(element.type) ? element.value : "",
      element.getAttribute("placeholder"), field ? "" : element.textContent,
      [...element.querySelectorAll("img[alt]")].map((image) => image.alt).join(" ")]
      .some((text) => (text ?? "").trim().length > 0);
  };
  const describe = (element) => element.outerHTML.replace(/\\s+/gu, " ").slice(0, 160);
  const controls = [...document.querySelectorAll('button, a[href], input:not([type="hidden"]), select, textarea, [role="button"], [role="tab"], [role="checkbox"], [role="switch"], [role="menuitem"]')]
    .filter(visible);
  const ids = [...document.querySelectorAll("[id]")].map((element) => element.id);
  return {
    controls: controls.length,
    unnamed: controls.filter((element) => !nameOf(element)).map(describe).slice(0, 6),
    imagesWithoutAlt: [...document.querySelectorAll("img")].filter((image) => visible(image) && !image.hasAttribute("alt")).map(describe).slice(0, 6),
    duplicateIds: [...new Set(ids.filter((id, index) => ids.indexOf(id) !== index))].slice(0, 6),
    heading: [...document.querySelectorAll("main.content h1, main.content h2, main.content [role='heading']")].some(visible),
  };
})()`;

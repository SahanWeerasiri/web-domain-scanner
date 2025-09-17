from Wappalyzer import Wappalyzer, WebPage
def fingerprint_technology(url):
    """Fingerprint web technologies used by a website using Wappalyzer."""
    try:
        wappalyzer = Wappalyzer.latest()
        webpage = WebPage.new_from_url(url)
        technologies = wappalyzer.analyze(webpage)
        print(f"Technologies for {url}: {technologies}")
        return technologies
    except Exception as e:
        print(f"Error analyzing {url}: {e}")
        return None
# webpage = WebPage.new_from_url(url)
# technologies = wappalyzer.analyze(webpage)
# print(technologies) # Outputs a dict like {'PHP': {'version': '8.1'}, 'jQuery': {...}}
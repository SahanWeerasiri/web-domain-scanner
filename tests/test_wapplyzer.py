from Wappalyzer import Wappalyzer, WebPage
wappalyzer = Wappalyzer.latest()
url = 'https://pornhub.com'
webpage = WebPage.new_from_url(url)
technologies = wappalyzer.analyze(webpage)
print(technologies) # Outputs a dict like {'PHP': {'version': '8.1'}, 'jQuery': {...}}
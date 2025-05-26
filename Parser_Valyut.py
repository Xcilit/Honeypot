from bs4 import BeautifulSoup
import requests

url = 'https://www.cbr.ru/currency_base/daily/'
page = requests.get(url)
print(page.status_code)
filteredNews = []
allNews = []
Final = []
soup = BeautifulSoup(page.text, 'html.parser')
print(soup)
allNews = soup.find_all('td')
print(allNews)
filteredNews = [td.get_text(strip=True) for td in allNews]
# for data in allNews:
#     if data.find('td', "/td") is not None:
#         filteredNews.append(data.text)
Final = []
dollar = "840"
if dollar in filteredNews:
    index = filteredNews.index(dollar)
    if index + 1 < len(filteredNews):
        Final.append(filteredNews[index + 1])
        Final.append(filteredNews[index+4])
print(filteredNews)
print(Final)
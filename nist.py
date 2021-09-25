from requests_html import HTMLSession
from bs4 import BeautifulSoup
from colorama import Fore, Style

# change the color of the text
def check_level_cve(text):
    if 'CRITICAL' in text:
        return text.replace("CRITICAL", "{}CRITICAL{}".format(Fore.RED, Fore.RESET))
    elif 'HIGH' in text:
        return text.replace("HIGH", "{}HIGH{}".format(Fore.YELLOW, Fore.RESET))
    elif 'MEDIUM' in text:
        return text.replace("MEDIUM", "{}MEDIUM{}".format(Fore.GREEN, Fore.RESET))
    elif 'score not found' in text:
        return text.replace("score not found", "{}score not found{}".format(Fore.MAGENTA, Fore.RESET))
    else:
        pass

s= HTMLSession()

def find_cve():
    while True:
        arsenal = input("Q to quit or E to enter: ")
        if arsenal.strip().upper() == 'Q':
            print('bye :)')
            break
        elif arsenal.strip().upper() == 'E':
            user_input = input('enter cve: ')
            url = 'https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&query={}&search_type=all&isCpeNameSearch=false'.format(
                user_input)
            request = s.get(url)
            soup = BeautifulSoup(request.text, 'html.parser')

            search_results = soup.find('div', id='vulnerability-search-results-div').find('table', {'class': 'table table-striped table-hover'}).tbody.contents
            resulte = {}
            for line in search_results:
                if line == '\n':
                    pass
                else:
                    cve_name = line.th.a.string
                    info_cve = 'info_cve: {}'.format(line.td.p.string)
                    cve_score = line.find("span", {"id": "cvss3-link"})
                    resulte[cve_name] = []
                    if cve_score is None:
                        cve_score = 'cve V3.1: score not found'
                        resulte[cve_name].append(cve_score)
                    else:
                        cve_score = 'cve score V3.1: {}'.format(cve_score.a.string)
                        resulte[cve_name].append(cve_score)

                    cve_published_date = 'Published: {}'.format(str(line.td.span.string)[0:-8])
                    resulte[cve_name].append(info_cve)
                    cve_url = 'https://nvd.nist.gov/' + line.th.strong.a['href']
                    resulte[cve_name].append(cve_url)
                    resulte[cve_name].append(cve_published_date)

            # find cwe id & cwe score
            for cve_name, cve_url in resulte.items():
                url = cve_url[-2]
                cwe_id, cwe_name = 'NVD-CWE-ID-NOT-FOUND', 'NVD-CWE-NOT-FOUND'
                secend_request = s.get(url)
                page = BeautifulSoup(secend_request.text, 'html.parser')
                # try to find cwe detiles
                try:
                    cwe = page.find('div', {'id': 'vulnTechnicalDetailsDiv'}).tbody.tr.findChildren()
                    cwe_id = 'cwe_id: {}'.format(cwe[0].a.string)

                    cwe_name = 'cwe_name: {}'.format(cwe[2].string)
                    cwe_link = page.find('div', {'id': 'vulnHyperlinksPanel'}).tbody.tr.td.a['href']
                    cwe_link = 'cwe_link: {}'.format(cwe_link)

                    # update cwe detiles to the resulte dict[cve_name]
                    resulte[cve_name].append(cwe_id)
                    resulte[cve_name].append(cwe_name)
                    resulte[cve_name].append(cwe_link)
                except:
                    # return defulte value if cve detiles not found
                    resulte[cve_name].append(cwe_id)
                    resulte[cve_name].append(cwe_name)
                    resulte[cve_name].append('cwe link not found')
            #printing cve & cwe info
            for cve, cve_detile in reversed(resulte.items()):
                resulte[cve_name][2] = 'url info: ' +resulte[cve_name][2]
                cve_detile[0] = check_level_cve(cve_detile[0])
                print(cve, '\n', cve_detile[0], '\n', cve_detile[1], '\n', cve_detile[2], '\n', cve_detile[3] ,'\n', cve_detile[4] ,'\n', cve_detile[5] ,'\n', cve_detile[6])

                print('=====================================================================================================================================================')

        else:
            print(Fore.RED + 'incorrect value')
            print(Style.RESET_ALL)



def main():
    y = find_cve()

if __name__ == '__main__':
     main()

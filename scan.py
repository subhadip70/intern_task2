import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import sys

s = requests.session()
s.headers["user-agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36"

#get all the forms 
def get_forms(url):
    soup = BeautifulSoup(s.get(url).content,"html.parser")
    return soup.find_all("form")

#get all the details from the form
def form_details(form):
    detailsOfForm = {}
    action = form.attrs.get("action")
    method = form.attrs.get("method","get")
    inputs = []

    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type","text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value","")
        inputs.append({
            "type":input_type,
            "name":input_name,
            "value":input_value
            })
        detailsOfForm["action"] = action
        detailsOfForm["method"] = method
        detailsOfForm["inputs"] = inputs
        return detailsOfForm
    

def vulnerable(reponse):
    errors ={"quoted string no properly terminated",
             "unclose quotation mark after the charecter string",
             "you have an error in your sql syntax"}
    for error in errors:
        if error in reponse.content.decode().lower():
            return True
    return False

def sql_scan(url):
    forms = get_forms(url)
    print(f"[+] Detected {len(forms)} forms on {url}.")

    for form in forms:
        details = form_details(form)

        for i in "\"'":
            data ={}
            for input in details["inputs"]:
                if input["type"] == "text" or input["type"] == "hidden" or input["value"]:
                    data[input["name"]] = input["value"]+i
                elif input["type"] != "submit":
                    data[input["name"]] = f"test{i}"
            print(url)
            form_details(form)

            if details["method"] == "post":
                res = s.post(url,data=data)
            elif details["method"] == "get":
                res = s.get(url,params=data)

            if vulnerable(res):
                print("SQL injection vulnerability detected on '{url}'")
            else:
                print("No SQL injection vulnerability detected on '{url}'")
                break


if __name__ == "__main__":
    url = input("Enter the URL to scan: ")
    sql_scan(url)

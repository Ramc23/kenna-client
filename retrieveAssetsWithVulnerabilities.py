import requests
import json
import jxmlease
import csv
import xml.etree.ElementTree as ET
import re
import time
import logging
import csv
import os
import argparse

logger = logging.getLogger(__name__)

class downloadKennaLogs:

    def __init__(self, args):
        self.token = args['token']
        self.mount_dir = args['mount_dir']
        self.asset_count = 0
        self.tempAsset = {
                            'asset' : ''
                         }
        if(args['url'] is None):
            self.assetUrl = "https://api.eu.kennasecurity.com/assets/?page=1"
            self.base_url = "https://api.eu.kennasecurity.com/assets/"
        else:
            self.base_url = args['url'] + "/"
            self.assetUrl = args['url'] + "/?page=1"
        self.hasPageToDownload = True        
        
    def getAssetResponse(self):
                
        while(self.hasPageToDownload):            
            dataJson = self.getKennaResources(self.assetUrl)
            
            self.hasPageToDownload = self.checkHasPageToDownload(dataJson)            
            
            for assetData in dataJson['assets']:
                assetId = assetData['id']
                print(assetId)
                
                self.getVulnerabilitiesForAsset(assetId, assetData) 


    def generateHeader(self):
        '''
        generates Header for Kenna API requests
        needs secured previlaged token to access the API
        
        '''

        header = {
            'X-Risk-Token': self.token,
            'content-Type' : 'application/json'
        }
        return header

    def checkHasPageToDownload(self, dataJson):
        '''
        Check for continuvation pages using the meta data from the Kenna API response.
        If more pages are there, iterate page number to download the resources

        '''

        if(dataJson['meta']['pages'] >= dataJson['meta']['page']):
            total_pages = dataJson['meta']['pages']
            current_page = dataJson['meta']['page']
            print(" Total Assets pages - " + str(total_pages))
            print(" Downloaded asset in page - "+ str(current_page))

            self.assetUrl = self.base_url + "?page=" + str(current_page + 1)
        
        if (total_pages > current_page):
            return True
        else:
            return False
    
    def getKennaResources(self, url):
        '''
        Queries the Kenna API for various resources - Asset, Vulneriablities, Fixes

        '''

        resourceResponse = requests.get(url, headers=self.generateHeader())

        if self.checkResponse(resourceResponse) == "OK":
            responseJson = resourceResponse.json()
        else:
            print("ERROR")
            exit()
        return responseJson

    def checkResponse(self, response):
        '''
        check the response from Kenna API
        handle the various response code from the HTTP call

        '''

        print("response from Kenna API: " + str(response))

        if response.status_code == requests.codes.ok:
            return "OK"
        if response.status_code == requests.codes.too_many_requests:
            return "RETRY"
        if response.status_code == requests.codes.unauthorized:
            print("check the access token - Unauthorised")
            return "ERROR"
        if response.status_code == requests.codes.not_found:
            print("No data available")
            return "UNAVAILABLE"
        if response.status_code == requests.codes.bad_request:
            print("Check the request - Invalid")
            return "ERROR"
        if response.status_code == requests.codes.internal_server_error:
            print(" Internal server error")
            return "ERROR"
        
        return "ERROR"

    def getVulnerabilitiesForAsset(self, assetId, assetData):

        vulnerabilityUrl = self.base_url + str(assetId) + "/vulnerabilities"
        vulnerabilityJson = self.getKennaResources(vulnerabilityUrl)

        for x in vulnerabilityJson['vulnerabilities']:
            x.pop('urls')
            x.pop('asset_id')
        
        assetData['vulnerability_info'] = assetData.pop('urls')
        assetData['vulnerability_info'] = vulnerabilityJson

        self.tempAsset['asset'] = assetData
        temp_file_path = os.path.join(self.mount_dir, "data_file.json")

        with open(temp_file_path, "w") as write_file:
            json.dump(self.tempAsset, write_file)

        with open(temp_file_path) as json_file:
            dict_data = json.load(json_file)

        data_xml = jxmlease.emit_xml(dict_data)
        
        self.writeToFile(data_xml, assetId)


    def writeToFile(self, dataXML, assetId):
        file_path = os.path.join(self.mount_dir, 'asset_id_' + str(assetId) + '_vulnerablities.xml')
        file = open(file_path, "w")
        try:
            file.write(dataXML)
        except UnicodeError:
            dataXML = dataXML.encode('utf-8', 'ignore')
            file.write(dataXML)
        file.close()
                
        if file.closed:
            print("Asset saved for assetId: "+ str(assetId))
        else:
            file.close()
            print("Asset not saved: "+ str(assetId))
            ## retry for the assetId
        
        file.close()


    def getFixes(self, fixId):
        fixUrl = "https://api.eu.kennasecurity.com/fixes/" + str(fixId)
        fixJson = self.getKennaResources(fixUrl)
        
        if 'assets' in fixJson['fix']:
            fixJson['fix'].pop('assets', None)
        
        print(fixJson)

        

def parse_args():
    """Parse command line arguments passed to script invocation."""
    parser = argparse.ArgumentParser(
        description='Kenna Client.')

    parser.add_argument('destination_dir', help='destination directory')
    parser.add_argument('token', help='secure token')
    parser.add_argument('asset_url', nargs='?', help='asset url')

    return parser.parse_args()

def main():
    """Module's main entry point """
    url = None
    args = parse_args()
    destination_dir = args.destination_dir
    token = args.token
    if args.asset_url is not None:
        url = args.asset_url


    if not os.path.exists(destination_dir):
        raise Exception('Directory does not exist ({0}).'.format(destination_dir))
    
    if token is None:
        raise Exception('Token cant be null. Provide a active kenna token')

    args = { "token" :token ,
        "mount_dir" : destination_dir ,
        "url" : url
        }
    extractlog = downloadKennaLogs(args)
    extractlog.getAssetResponse()

if __name__ == '__main__':
    main()




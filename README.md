# Overview

This script helps to download resources from Kenna REST API

# Prerequisite 
    Python
        jxmlease
        ElementTree

# Running
    python retrieveAssetsWithVulnerabilities.py <arguments>

## arguments
        <destination_dir>  <token> <asset_url>

            <destination_dir>  : directory where details needs to be downloaded
            <token> : valid Kenna API Token
            <asset_url> : Kenna API url to download asset (optional)
        
## Kenna API details

    Kenna API has details about Assets, vulnerablites and fixes.

    This script queries Assets page by page and queries vulnerablities related to every asset.

    The final output xml will have Asset details + vulnerablity Infos

    For every asset, there will be an output xml

## Kenna API Links
    https://api.kennasecurity.com/introduction

## Limitation

    This script will download maximum assets of 20 pages (500 per page) as Kenna API has restriction

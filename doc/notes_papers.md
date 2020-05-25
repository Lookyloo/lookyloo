# AdGraph

## Implementation

* https://github.com/uiowa-irl/AdGraph

4000+ lines of patch on Chromium version 69.0.3441.0 (released 25 May 2018)

## Paper

* https://umariqbal.com/papers/adgraph-sp2020.pdf

## Key points for lookyloo

### Static, node by node

* features of the node
* keywords in URL
* keywords in content
* length & parameters of the URL
* On image: OCR (?)

* Domain => blocklists (ublock)

* Javascript analysis:
  * eval
  * specific keywords (tracking, ads, fingerprint...)
  * specific JS calls (track mouse, scrolling)
  * Async calls are very often used by ads, recommandation: https://www.iab.com/wp-content/uploads/2017/08/IABNewAdPortfolio_FINAL_2017.pdf
  * /!\ anything obfuscated is just under the radar

### Dynamic, pased on the tree

* size
* position in the tree
* parent features
* siblings
* number and type of children

# Other ressources

* Ads standards: https://github.com/InteractiveAdvertisingBureau - https://iabtechlab.com/standards/
* Standard API for Ads bidding: https://github.com/prebid/

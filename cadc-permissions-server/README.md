# cadc-permissions-server

This is the server side component that is used by the cadc-permissions-client to get
grant information for an asset.

## REST API

The API is a simple HTTP GET request with exactly two parameters:

* ID = {URI of the asset}
* OP = read|write

The response is an XML document that can be written and read by the cadc-permissions
library; there is currently no schema so for now the document format is an implementation
detail and the library should be used for parsing and serialization.

## server-side code

Since the API is so simple, we are not planning to provide an implementation beyond the supporting
code in the cadc-permissions library.

There is a rules-based service that implements the REST API with static configuration:
<a href="https://github.com/opencadc/storage-inventory/tree/master/baldur">baldur</a>




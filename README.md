Beebotte JS Client
==================

| what          | where                                     |
|---------------|-------------------------------------------|
| overview      | http://beebotte.com/overview              |
| tutorials     | http://beebotte.com/tutorials             |
| apidoc        | http://beebotte.com/docs/clientapi        |
| source        | https://github.com/beebotte/bbt_client_js |

### Bugs / Feature Requests

Think you.ve found a bug? Want to see a new feature in beebotte? Please open an
issue in github. Please provide as much information as possible about the issue type and how to reproduce it.

    https://github.com/beebotte/bbt_client_js/issues

## Install

Clone the source code from github, and add the source code to your project

    git clone https://github.com/beebotte/bbt_client_js.git

Include it directly from beebotte

    <script type="text/javascript" src="//beebotte.com/bbt.js"></script>

OR the minimified version

    <script type="text/javascript" src="//beebotte.com/bbt.min.js"></script>

## Usage
To fully use Beebotte, you need to be a registered user. If this is not the case, create your account at <https://beebotte.com> and note your access credentials.

As a reminder, Beebotte resource description uses a two levels hierarchy:

* Channel: physical or virtual connected object (an application, an arduino, a coffee machine, etc) providing some resources
* Resource: most elementary part of Beebotte, this is the actual data source (e.g. temperature from a domotics sensor)

For documentation, check the links under:

    https://beebotte.com/overview

## Dependencies
Beebotte Javascript client library uses [Socket.io 1.0](http://socket.io/) and jQuery. You need to include them as well.

## License
Copyright 2013 - 2014 Beebotte.

[The MIT License](http://opensource.org/licenses/MIT)

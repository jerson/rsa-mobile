const express = require('express');
express.static.mime.define({'application/wasm': ['wasm']});
var app = express();

app.use('/', express.static('public'));

app.listen(3000, function () {
    console.log('Wasm app listening on port 3000!')
});
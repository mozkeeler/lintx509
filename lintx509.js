var atob = require("atob");

const UNIVERSAL = 0 << 6;
const CONSTRUCTED = 1 << 5;
const CONTEXT_SPECIFIC = 2 << 6;

const SEQUENCE = UNIVERSAL | CONSTRUCTED | 0x10; // 0x30
const BOOLEAN = UNIVERSAL | 0x01; // 0x01
const INTEGER = UNIVERSAL | 0x02; // 0x02
const OCTETSTRING = UNIVERSAL | 0x04; // 0x04
const BITSTRING = UNIVERSAL | 0x03; // 0x03
const NULL = UNIVERSAL | 0x05; // 0x05
const OID = UNIVERSAL | 0x06; // 0x06
const UTCTime = UNIVERSAL | 0x17; // 0x17
const GeneralizedTime = UNIVERSAL | 0x18; // 0x18

const ERROR_DATA_TRUNCATED = "error: data truncated";
const ERROR_UNEXPECTED_TAG = "error: unexpected tag";
const ERROR_UNSUPPORTED_ASN1 = "error: unsupported asn.1";
const ERROR_INVALID_LENGTH = "error: invalid length";
const ERROR_UNSUPPORTED_LENGTH = "error: unsupported length";
const ERROR_EXTRA_DATA = "error: extra data";
const ERROR_NULL_WITH_DATA = "error: NULL tag containing data";
const ERROR_UNSUPPORTED_X509_FEATURE = "error: unsupported x509 feature";
const ERROR_TIME_NOT_UTCTIME_OR_GENERALIZED_TIME = "error: Time not UTCTime or GeneralizedTime";
const ERROR_TIME_NOT_VALID = "error: Time not valid";
const ERROR_INVALID_BOOLEAN_ENCODING = "error: invalid BOOLEAN encoding";
const ERROR_INVALID_BOOLEAN_VALUE = "error: invalid BOOLEAN value";

var der = function(bytes) {
  this._bytes = bytes;
  this._cursor = 0;
};

der.prototype = {

  readByte: function() {
    if (this._cursor >= this._bytes.length) {
      throw ERROR_DATA_TRUNCATED;
    }
    var val = this._bytes[this._cursor];
    this._cursor++;
    //console.log("read " + val + ". Cursor is now at " + this._cursor);
    return val;
  },

  _readExpectedTag: function(expectedTag) {
    var tag = this.readByte();
    if (tag != expectedTag) {
      throw ERROR_UNEXPECTED_TAG;
    }
  },

  _readLength: function() {
    var nextByte = this.readByte();
    if (nextByte < 0x80) {
      return nextByte;
    }
    if (nextByte == 0x80) {
      throw ERROR_UNSUPPORTED_ASN1;
    }
    if (nextByte == 0x81) {
      var length = this.readByte();
      if (length < 0x80) {
        throw ERROR_INVALID_LENGTH;
      }
      return length;
    }
    if (nextByte == 0x82) {
      var length1 = this.readByte();
      var length2 = this.readByte();
      var length = (length1 << 8) | length2;
      if (length < 256) {
        throw ERROR_INVALID_LENGTH;
      }
      return length;
    }
    throw ERROR_UNSUPPORTED_LENGTH;
  },

  _readBytes: function(length) {
    if (this._cursor > this._bytes.length - length) {
      throw ERROR_DATA_TRUNCATED;
    }
    var contents = this._bytes.slice(this._cursor, this._cursor + length);
    this._cursor += length;
    //console.log("read " + length + " bytes. Cursor is now at " + this._cursor);
    return contents;
  },

  _readTagAndGetContents: function(tag) {
    this._readExpectedTag(tag);
    var length = this._readLength();
    var contents = this._readBytes(length);
    return contents;
  },

  _peekByte: function() {
    if (this._cursor >= this._bytes.length) {
      throw ERROR_DATA_TRUNCATED;
    }
    return this._bytes[this._cursor];
  },

  readExpectedTLV: function(tag) {
    var mark = this._cursor;
    this._readExpectedTag(tag);
    var length = this._readLength();
    // read the bytes so we know they're there (also to advance the cursor)
    this._readBytes(length);
    var tlv = this._bytes.slice(mark, this._cursor);
    return new der(tlv);
  },

  readTLV: function() {
    var nextTag = this._peekByte();
    return this.readExpectedTLV(nextTag);
  },

  readTLVChoice: function(tagList) {
    var tag = this._peekByte();
    if (tagList.indexOf(tag) == -1) {
      throw ERROR_UNEXPECTED_TAG;
    }
    return this.readExpectedTLV(tag);
  },

  peekTag: function(tag) {
    if (this._cursor >= this._bytes.length) {
      return false;
    }
    return this._bytes[this._cursor] == tag;
  },

  assertAtEnd: function() {
    if (this._cursor != this._bytes.length) {
      throw ERROR_EXTRA_DATA;
    }
  },

  atEnd: function() {
    return this._cursor == this._bytes.length;
  },

  readSEQUENCE: function() {
    return new der(this._readTagAndGetContents(SEQUENCE));
  },

  readINTEGER: function() {
    // TODO: validate contents, handle negative values
    // TODO: handle restrictions on values
    var contents = this._readTagAndGetContents(INTEGER);
    // If it's too long to represent in 64 bits, return as an array of bytes.
    if (contents.length > 7) {
      return contents;
    }
    var value = 0;
    while (contents.length > 0) {
      value *= 256;
      value += contents.shift();
    }
    return value;
  },

  readBOOLEAN: function() {
    var contents = this._readTagAndGetContents(BOOLEAN);
    if (contents.length != 1) {
      throw ERROR_INVALID_BOOLEAN_ENCODING;
    }
    if (contents[0] != 0 || contents[0] != 0xff) {
      throw ERROR_INVALID_BOOLEAN_VALUE;
    }
    return contents[0];
  },

  readGivenTag: function(tag) {
    return new der(this._readTagAndGetContents(tag));
  },

  readBITSTRING: function() {
    var contents = this._readTagAndGetContents(BITSTRING);
    var unusedBits = contents[0];
    if (unusedBits != 0) {
      throw ERROR_UNSUPPORTED_ASN1;
    }
    return contents.slice(1, contents.length);
  },

  readOCTETSTRING: function() {
    return this._readTagAndGetContents(OCTETSTRING);
  },

  readOID: function() {
    var contents = this._readTagAndGetContents(OID);
    return new oid(contents);
  },

  readNULL: function() {
    var contents = this._readTagAndGetContents(NULL);
    if (contents.length != 0) {
      throw ERROR_NULL_WITH_DATA;
    }
    return null;
  },
};

var oid = function(bytes) {
  this._values = [];
  // First octet has value 40 * value1 + value2
  // TODO: range checks on the input
  var value1 = Math.floor(bytes[0] / 40);
  var value2 = bytes[0] - 40 * value1;
  this._values.push(value1);
  this._values.push(value2);
  bytes.shift();
  var accumulator = 0;
  // TODO: lots more checks up in here
  while (bytes.length > 0) {
    var value = bytes.shift();
    accumulator *= 128;
    if (value > 128) {
      accumulator += (value - 128);
    } else {
      accumulator += value;
      this._values.push(accumulator);
      accumulator = 0;
    }
  }
}

oid.prototype = {
  _dottedStringToDescription: {
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    "2.5.29.30": "id-ce-nameConstraints",
    "2.5.29.37": "id-ce-extKeyUsage",
  },

  asDottedString: function() {
    return this._values.join(".");
  },

  toString: function() {
    var dottedString = this.asDottedString();
    if (dottedString in this._dottedStringToDescription) {
      return this._dottedStringToDescription[dottedString];
    }
    return "unknown OID (" + dottedString + ")";
  },
};

var Certificate = function(bytes) {
  this._der = new der(bytes);
  this._tbsCertificate = null;
  this._signatureAlgorithm = null;
  this._signatureValue = null;
};

Certificate.prototype = {
  parse: function() {
    var contents;
    try {
      contents = this._der.readSEQUENCE();
    } catch (e) {
      console.log("error parsing Certificate");
      throw e;
    }
    try {
      this._tbsCertificate = new TBSCertificate(contents.readTLV());
      this._tbsCertificate.parse();
    } catch (e) {
      console.log("error parsing tbsCertificate");
      throw e;
    }

    try {
      this._signatureAlgorithm = new AlgorithmIdentifier(contents.readTLV());
      this._signatureAlgorithm.parse();
    } catch (e) {
      console.log("error parsing signatureAlgorithm");
      throw e;
    }

    try {
      this._signatureValue = contents.readBITSTRING();
    } catch (e) {
      console.log("error parsing signatureValue");
      throw e;
    }
    contents.assertAtEnd();
    this._der.assertAtEnd();
  },
};

var TBSCertificate = function(der) {
  this._der = der;
  this._version = null;
};

TBSCertificate.prototype = {
  parse: function() {
    var contents;
    try {
      contents = this._der.readSEQUENCE();
    } catch (e) {
      console.log("error parsing TBSCertificate");
      throw e;
    }

    try {
      var versionTag = CONTEXT_SPECIFIC | CONSTRUCTED | 0;
      if (!contents.peekTag(versionTag)) {
        this._version = 1;
      } else {
        var versionContents = contents.readGivenTag(versionTag);
        this._version = versionContents.readINTEGER() + 1;
        versionContents.assertAtEnd();
      }
    } catch (e) {
      console.log("error parsing version");
      throw e;
    }

    try {
      this._serialNumber = contents.readINTEGER();
    } catch (e) {
      console.log("error parsing serialNumber");
      throw e;
    }

    try {
      this._signature = new AlgorithmIdentifier(contents.readTLV());
      this._signature.parse();
    } catch (e) {
      console.log("error parsing signature");
      throw e;
    }

    try {
      this._issuer = new Name(contents.readTLV());
      this._issuer.parse();
    } catch (e) {
      console.log("error parsing issuer");
      throw e;
    }

    try {
      this._validity = new Validity(contents.readTLV());
      this._validity.parse();
    } catch (e) {
      console.log("error parsing validity");
      throw e;
    }

    try {
      this._subject = new Name(contents.readTLV());
      this._subject.parse();
    } catch (e) {
      console.log("error parsing subject");
      throw e;
    }

    try {
      this._subjectPublicKeyInfo = new Name(contents.readTLV());
      this._subjectPublicKeyInfo.parse();
    } catch (e) {
      console.log("error parsing subjectPublicKeyInfo");
      throw e;
    }

    var issuerUniqueIDTag = CONTEXT_SPECIFIC | CONSTRUCTED | 1;
    if (contents.peekTag(issuerUniqueIDTag)) {
      console.log("TBSCertificate.issuerUniqueID not supported");
      throw ERROR_UNSUPPORTED_X509_FEATURE;
    }
    var subjectUniqueIDTag = CONTEXT_SPECIFIC | CONSTRUCTED | 2;
    if (contents.peekTag(subjectUniqueIDTag)) {
      console.log("TBSCertificate.subjectUniqueID not supported");
      throw ERROR_UNSUPPORTED_X509_FEATURE;
    }

    var extensionsTag = CONTEXT_SPECIFIC | CONSTRUCTED | 3;
    if (contents.peekTag(extensionsTag)) {
      try {
        var extensionSequence = contents.readGivenTag(extensionsTag);
        var extensions = extensionSequence.readSEQUENCE();
        extensionSequence.assertAtEnd();
        this._extensions = [];
        while (!extensions.atEnd()) {
          var extension = new Extension(extensions.readTLV());
          extension.parse();
          this._extensions.push(extension);
        }
      } catch (e) {
        console.log("error parsing extensions");
        throw e;
      }
    }
    contents.assertAtEnd();
    this._der.assertAtEnd();
  },
};

var AlgorithmIdentifier = function(der) {
  this._der = der;
  this._oid = null;
  this._params = null;
};

AlgorithmIdentifier.prototype = {
  parse: function() {
    var contents;
    try {
      contents = this._der.readSEQUENCE();
    } catch (e) {
      console.log("error parsing AlgorithmIdentifier");
      throw e;
    }
    try {
      this._oid = contents.readOID();
    } catch (e) {
      console.log("error parsing OID");
      throw e;
    }
    if (!contents.atEnd()) {
      try {
        this._params = contents.readNULL();
      } catch (e) {
        console.log("error parsing params assumed to be NULL");
        throw e;
      }
    }
    contents.assertAtEnd();
    this._der.assertAtEnd();
  },
};

var Name = function(der) {
  this._der = der;
};

Name.prototype = {
  parse: function() {
  },
};

// TODO: Validate that the Time doesn't specify a nonexistent month/day/etc.
var Time = function(der) {
  this._der = der;
  this._year = null;
  this._month = null;
  this._hour = null;
  this._minutes = null;
  this._seconds = null;
};

Time.prototype = {
  parse: function() {
    var tag;
    if (this._der.peekTag(UTCTime)) {
      tag = UTCTime;
    } else if (this._der.peekTag(GeneralizedTime)) {
      tag = GeneralizedTime;
    } else {
      throw  ERROR_TIME_NOT_UTCTIME_OR_GENERALIZED_TIME;
    }
    try {
      var contents = this._der.readGivenTag(tag);
      if (tag == UTCTime) {
        // UTCTime is YYMMDDHHMMSSZ in RFC 5280. If YY is greater than or equal
        // to 50, the year is 19YY. Otherwise, it is 20YY.
        var y1 = this._validateDigit(contents.readByte());
        var y2 = this._validateDigit(contents.readByte());
        var yy = y1 * 10 + y2;
        if (yy >= 50) {
          this._year = 1900 + yy;
        } else {
          this._year = 2000 + yy;
        }
      } else {
        // GeneralizedTime is YYYYMMDDHHMMSSZ in RFC 5280.
        this._year = 0;
        for (var i = 0; i < 4; i++) {
          var y = this._validateDigit(contents.readByte());
          this._year = this._year * 10 + y;
        }
      }

      var m1 = this._validateDigit(contents.readByte());
      var m2 = this._validateDigit(contents.readByte());
      this._month = m1 * 10 + m2;

      var d1 = this._validateDigit(contents.readByte());
      var d2 = this._validateDigit(contents.readByte());
      this._day = d1 * 10 + d2;
      
      var h1 = this._validateDigit(contents.readByte());
      var h2 = this._validateDigit(contents.readByte());
      this._hour = h1 * 10 + h2;
      
      var min1 = this._validateDigit(contents.readByte());
      var min2 = this._validateDigit(contents.readByte());
      this._minutes = min1 * 10 + min2;
      
      var s1 = this._validateDigit(contents.readByte());
      var s2 = this._validateDigit(contents.readByte());
      this._seconds = s1 * 10 + s2;

      var z = contents.readByte();
      if (z != 'Z'.charCodeAt(0)) {
        console.log("error parsing Time: not Zulu");
        throw ERROR_TIME_NOT_VALID;
      }
      
      contents.assertAtEnd();
      this._der.assertAtEnd();
    } catch (e) {
      console.log("error parsing Time");
      throw e;
    }
  },

  // Takes a byte that is supposed to be in the ASCII range for '0' to '9'.
  // Validates the range and then converts it to the range 0 to 9.
  _validateDigit: function(d) {
    if (d < '0'.charCodeAt(0) || d > '9'.charCodeAt(0)) {
      console.log("error parsing Time: invalid digit '" + d + "'");
      throw ERROR_TIME_NOT_VALID;
    }
    return d - '0'.charCodeAt(0);
  },
};

var Validity = function(der) {
  this._der = der;
  this._notBefore = null;
  this._notAfter = null;
};

Validity.prototype = {
  parse: function() {
    var contents;
    try {
      contents = this._der.readSEQUENCE();
    } catch (e) {
      console.log("error parsing Validity");
      throw e;
    }
    try {
      this._notBefore = new Time(contents.readTLVChoice([UTCTime, GeneralizedTime]));
      this._notBefore.parse();
    } catch (e) {
      console.log("error parsing notBefore");
      throw e;
    }
    try {
      this._notAfter = new Time(contents.readTLVChoice([UTCTime, GeneralizedTime]));
      this._notAfter.parse();
    } catch (e) {
      console.log("error parsing notAfter");
      throw e;
    }
    contents.assertAtEnd();
    this._der.assertAtEnd();
  },
};

var Extension = function(der) {
  this._der = der;
  this._oid = null;
  this._critical = null;
  this._value = null;
};

Extension.prototype = {
  parse: function() {
    var contents;
    try {
      contents = this._der.readSEQUENCE();
    } catch (e) {
      console.log("error parsing Extension");
      throw e;
    }
    try {
      this._oid = contents.readOID();
    } catch (e) {
      console.log("error parsing extnID");
      throw e;
    }
    try {
      // TODO: check for explicit encoding of DEFAULT FALSE
      if (contents.peekTag(BOOLEAN)) {
        this._critical = contents.readBOOLEAN();
      } else {
        this._critical = false;
      }
    } catch (e) {
      console.log("error parsing critical");
      throw e;
    }
    try {
      this._value = contents.readOCTETSTRING();
    } catch (e) {
      console.log("error parsing extnValue");
      throw e;
    }
    contents.assertAtEnd();
    this._der.assertAtEnd();
  },
};

function pemToBytes(pem) {
  var base64 = pem.replace("-----BEGIN CERTIFICATE-----", "")
                  .replace("-----END CERTIFICATE-----", "")
                  .replace(/[\r\n]/g, "");
  var binary = atob(base64);
  var bytes = [];
  for (var i = 0; i < binary.length; i++) {
    bytes.push(binary.charCodeAt(i));
  }
  return bytes;
}

var pem = "-----BEGIN CERTIFICATE-----\n" +
          "MIIDJDCCAg6gAwIBAgIUYU59M7KdJWUiKNA/d+dnnghmC1swCwYJKoZIhvcNAQEL\n" +
          "MA8xDTALBgNVBAMMBHJvb3QwIhgPMjAxMzA2MzAwMDAwMDBaGA8yMDE2MDcwNDAw\n" +
          "MDAwMFowPjE8MDoGA1UEAwwzVGVjaG5pY2FsbHkgQ29uc3RyYWluZWQgKGhhcyBk\n" +
          "TlNOYW1lIGFuZCBpUEFkZHJlc3MpMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB\n" +
          "CgKCAQEAuohRqESOFtZB/W62iAY2ED08E9nq5DVKtOz1aFdsJHvBxyWo4NgfvbGc\n" +
          "BptuGobya+KvWnVramRxCHqlWqdFh/cc1SScAn7NQ/weadA4ICmTqyDDSeTbuUzC\n" +
          "a2wO7RWCD/F+rWkasdMCOosqQe6ncOAPDY39ZgsrsCSSpH25iGF5kLFXkD3SO8Xg\n" +
          "uEgfqDfTiEPvJxbYVbdmWqp+ApAvOnsQgAYkzBxsl62WYVu34pYSwHUxowyR3bTK\n" +
          "9/ytHSXTCe+5Fw6naOGzey8ib2njtIqVYR3uJtYlnauRCE42yxwkBCy/Fosv5fGP\n" +
          "mRcxuLP+SSP6clHEMdUDrNoYCjXtjQIDAQABo0kwRzAdBgNVHSUEFjAUBggrBgEF\n" +
          "BQcDAgYIKwYBBQUHAwEwJgYDVR0eBB8wHaAbMA2CC2V4YW1wbGUuY29tMAqHCAoF\n" +
          "AAD//wAAMAsGCSqGSIb3DQEBCwOCAQEAdHoYHbnVK0SXsVZZ00IsN9B/eJi9XpRQ\n" +
          "bhX5KuDrZp+8xkzpan/iqq2M8ojDVO/jZScDlTCsjglDO2+KkANwsGdgDV4Obhyn\n" +
          "GZeK5/93A5PflULYuAH+tsgDGzyLcdhPKBLIRCQVAGqt5f3Y4iMDegVuCnHJSIj0\n" +
          "JWJtBm620HbvKHiJC1UUlnBuQPvJakx3KwKxa4rx0YoySRrM7/6GC3ZisLiVeJ5G\n" +
          "E/sAoKf7IijkfflhSFph24epzNW5+c28GE5/bqRY1+AyueWVswuRcVyoBZ7GOmGN\n" +
          "cKtPASFI0CUdEBTdVFTgkZ9SR5y/hkZsdo/TWeHviq/yJe0/qyB58Q==\n" +
          "-----END CERTIFICATE-----\n";

var bytes = pemToBytes(pem);
var cert = new Certificate(bytes);
cert.parse();
console.log(cert._tbsCertificate._extensions);
console.log(cert._tbsCertificate._extensions[0]._oid.toString());
console.log(cert._tbsCertificate._extensions[1]._oid.toString());
const UNIVERSAL = 0 << 6;
const CONSTRUCTED = 1 << 5;
const CONTEXT_SPECIFIC = 2 << 6;

const BOOLEAN = UNIVERSAL | 0x01; // 0x01
const INTEGER = UNIVERSAL | 0x02; // 0x02
const BITSTRING = UNIVERSAL | 0x03; // 0x03
const OCTETSTRING = UNIVERSAL | 0x04; // 0x04
const NULL = UNIVERSAL | 0x05; // 0x05
const OID = UNIVERSAL | 0x06; // 0x06
const UTF8String = UNIVERSAL | 0x0c; // 0x0c
const PrintableString = UNIVERSAL | 0x13; // 0x13
const TeletexString = UNIVERSAL | 0x14; // 0x14
const IA5String = UNIVERSAL | 0x16; // 0x16
const UTCTime = UNIVERSAL | 0x17; // 0x17
const GeneralizedTime = UNIVERSAL | 0x18; // 0x18
const SEQUENCE = UNIVERSAL | CONSTRUCTED | 0x10; // 0x30
const SET = UNIVERSAL | CONSTRUCTED | 0x11; // 0x31

const ERROR_LIBRARY_FAILURE = "error: library failure";
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
const ERROR_UNSUPPORTED_STRING_TYPE = "error: unsupported string type";
const ERROR_UNSUPPORTED_VERSION = "error: unsupported version";
const ERROR_UNSUPPORTED_EXTENSION_VALUE = "error: unsupported extension value";

const X509v3 = 2;

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

  readSET: function() {
    return new der(this._readTagAndGetContents(SET));
  },

  readINTEGER: function() {
    // TODO: validate contents, handle negative values
    // TODO: handle restrictions on values
    return this._readTagAndGetContents(INTEGER);
  },

  readBOOLEAN: function() {
    var contents = this._readTagAndGetContents(BOOLEAN);
    if (contents.length != 1) {
      throw ERROR_INVALID_BOOLEAN_ENCODING;
    }
    if (contents[0] != 0 && contents[0] != 0xff) {
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
    return "NULL";
  },

  readContents: function(tag) {
    return this._readTagAndGetContents(tag);
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
    "1.2.840.113549.1.1.1": "rsaEncryption",
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    "1.3.6.1.5.5.7.1.1": "id-pe-authorityInfoAccess",
    "2.5.29.14": "id-ce-subjectKeyIdentifier",
    "2.5.29.15": "id-ce-keyUsage",
    "2.5.29.17": "id-ce-subjectAlternativeName",
    "2.5.29.19": "id-ce-basicConstraints",
    "2.5.29.30": "id-ce-nameConstraints",
    "2.5.29.31": "id-ce-cRLDistributionPoints",
    "2.5.29.32": "id-ce-certificatePolicies",
    "2.5.29.35": "id-ce-authorityKeyIdentifier",
    "2.5.29.37": "id-ce-extKeyUsage",
    "2.5.4.3": "id-at-commonName",
    "2.5.4.5": "id-at-serialNumber",
    "2.5.4.6": "id-at-countryName",
    "2.5.4.7": "id-at-localityName",
    "2.5.4.8": "id-at-stateOrProvinceName",
    "2.5.4.9": "id-at-streetAddress",
    "2.5.4.10": "id-at-organizationName",
    "2.5.4.11": "id-at-organizationalUnitName",
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

var DisplayField = function(property, description, recurse) {
  this._property = property;
  this._description = description;
  this._recurse = recurse;
};

DisplayField.prototype = {
};

var Certificate = function(bytes) {
  this._der = new der(bytes);
  this._tbsCertificate = null;
  this._signatureAlgorithm = null;
  this._signatureValue = null;
  this._displayFields = [
    new DisplayField("_tbsCertificate", "tbsCertificate", true),
    new DisplayField("_signatureAlgorithm", "signatureAlgorithm", true),
    new DisplayField("_signatureValue", "signatureValue", false),
  ];
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
      this._signatureValue = new ByteArray(contents.readBITSTRING(), "");
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
  this._serialNumber = null;
  this._signature = null;
  this._issuer = null;
  this._validity = null;
  this._subject = null;
  this._subjectPublicKeyInfo = null;
  this._extensions = null;
  this._displayFields = [
    new DisplayField("_version", "version", false),
    new DisplayField("_serialNumber", "serialNumber", false),
    new DisplayField("_signature", "signature", true),
    new DisplayField("_issuer", "issuer", true),
    new DisplayField("_validity", "validity", true),
    new DisplayField("_subject", "subject", true),
    new DisplayField("_subjectPublicKeyInfo", "subjectPublicKeyInfo", true),
    new DisplayField("_extensions", "extensions", true),
  ];
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
        var versionBytes = versionContents.readINTEGER();
        if (versionBytes.length != 1 || versionBytes[0] != X509v3) {
          throw ERROR_UNSUPPORTED_VERSION;
        }
        this._version = 3;
        versionContents.assertAtEnd();
      }
    } catch (e) {
      console.log("error parsing version");
      throw e;
    }

    try {
      this._serialNumber = new ByteArray(contents.readINTEGER(), ":");
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
      this._subjectPublicKeyInfo = new SubjectPublicKeyInfo(
        contents.readTLV());
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
        this._extensions = new Extensions(extensionSequence.readTLV());
        this._extensions.parse();
        extensionSequence.assertAtEnd();
      } catch (e) {
        console.log("error parsing extensions");
        throw e;
      }
    }
    contents.assertAtEnd();
    this._der.assertAtEnd();
  },
};

function bytesToHexString(bytes, displayDelimiter) {
  var output = "";
  for (var i in bytes) {
    var hexByte = bytes[i].toString(16);
    if (hexByte.length == 1) {
      hexByte = "0" + hexByte;
    }
    output += (output.length != 0 ? displayDelimiter : "") + hexByte;
  }
  return output;
}

var ByteArray = function(bytes, displayDelimiter) {
  this._bytes = bytes;
  this._displayDelimiter = displayDelimiter;
};

ByteArray.prototype = {
  toString: function() {
    return bytesToHexString(this._bytes, this._displayDelimiter);
  },
};

var AlgorithmIdentifier = function(der) {
  this._der = der;
  this._oid = null;
  this._params = null;
  this._displayFields = [
    new DisplayField("_oid", "algorithm", false),
    new DisplayField("_params", "parameters", false),
  ];
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
  this._rdns = null;
  this._displayFields = [
    new DisplayField("_rdns", "RDN", true),
  ];
};

Name.prototype = {
  parse: function() {
    var contents;
    try {
      contents = this._der.readSEQUENCE();
    } catch (e) {
      console.log("error parsing Name");
      throw e;
    }
    try {
      this._rdns = [];
      while (!contents.atEnd()) {
        var rdn = new RDN(contents.readTLV());
        rdn.parse();
        this._rdns.push(rdn);
      }
    } catch (e) {
      console.log("error parsing Name");
      throw e;
    }
    contents.assertAtEnd();
    this._der.assertAtEnd();
  },
};

var RDN = function(der) {
  this._der = der;
  this._avas = null;
  this._displayFields = [
    new DisplayField("_avas", "AVA", true),
  ];
};

RDN.prototype = {
  parse: function() {
    var contents;
    try {
      contents = this._der.readSET();
    } catch (e) {
      console.log("error parsing RDN");
      throw e;
    }
    try {
      this._avas = [];
      while (!contents.atEnd()) {
        var ava = new AVA(contents.readTLV());
        ava.parse();
        this._avas.push(ava);
      }
    } catch (e) {
      console.log("error parsing RDN");
      throw e;
    }
    contents.assertAtEnd();
    this._der.assertAtEnd();
  },
};

var AVA = function(der) {
  this._der = der;
  this._type = null;
  this._value = null;
  this._displayFields = [
    new DisplayField("_type", "type", false),
    new DisplayField("_value", "value", false),
  ];
};

AVA.prototype = {
  parse: function() {
    var contents;
    try {
      contents = this._der.readSEQUENCE();
    } catch (e) {
      console.log("error parsing AVA");
      throw e;
    }
    try {
      this._type = contents.readOID();
      this._value = new StringType(contents.readTLV());
      this._value.parse();
    } catch (e) {
      console.log("error parsing AVA");
      throw e;
    }
    contents.assertAtEnd();
    this._der.assertAtEnd();
  },
};

var StringType = function(der) {
  this._der = der;
  this._type = null;
  this._value = null;
};

StringType.prototype = {
  parse: function() {
    try {
      if (this._der.peekTag(UTF8String)) {
        this._type = UTF8String;
      } else if (this._der.peekTag(PrintableString)) {
        this._type = PrintableString;
      } else if (this._der.peekTag(TeletexString)) {
        this._type = TeletexString;
      } else if (this._der.peekTag(IA5String)) {
        this._type = IA5String;
      } else {
        throw ERROR_UNSUPPORTED_STRING_TYPE;
      }
      // TODO: validate that the contents are actually valid for the type
      this._value = this._der.readContents(this._type);
    } catch (e) {
      console.log("error parsing string type");
      throw e;
    }
    this._der.assertAtEnd();
  },

  toString: function() {
    return utf8BytesToString(this._value);
  },
};

function utf8BytesToString(bytes) {
  var result = "";
  var i = 0;
  while (i < bytes.length) {
    var byte1 = bytes[i];
    i++;
    if ((byte1 >> 7) == 0) {
      // If the next byte is of the form 0xxxxxxx, this codepoint consists of
      // one byte.
      result += String.fromCharCode(byte1);
    } else if ((byte1 >> 5) == 6) {
      // If the next byte is of the form 110xxxxx, this codepoint consists of
      // two bytes. The other byte must be of the form 10xxxxxx.
      if (i >= bytes.length) {
        throw ERROR_INVALID_UTF8_ENCODING;
      }
      var byte2 = bytes[i];
      i++;
      if ((byte2 >> 6) != 2) {
        throw ERROR_INVALID_UTF8_ENCODING;
      }
      var codepoint = ((byte1 & 0x1F) << 6) + (byte2 & 0x3F);
      result += String.fromCharCode(codepoint);
    } else if ((byte1 >> 4) == 0x0E) {
      // If the next byte is of the form 1110xxxx, this codepoint consists of
      // three bytes. The next two bytes must be of the form 10xxxxxx 10xxxxxx.
      if (i >= bytes.length) {
        throw ERROR_INVALID_UTF8_ENCODING;
      }
      var byte2 = bytes[i];
      i++;
      if ((byte2 >> 6) != 2) {
        throw ERROR_INVALID_UTF8_ENCODING;
      }
      if (i >= bytes.length) {
        throw ERROR_INVALID_UTF8_ENCODING;
      }
      var byte3 = bytes[i];
      i++;
      if ((byte3 >> 6) != 2) {
        throw ERROR_INVALID_UTF8_ENCODING;
      }
      var codepoint = ((byte1 & 0x1F) << 12) + ((byte2 & 0x3F) << 6) +
                      (byte3 & 0x3F);
      result += String.fromCharCode(codepoint);
    } else {
      throw ERROR_INVALID_UTF8_ENCODING;
    }
  }
  return result;
}

// TODO: Validate that the Time doesn't specify a nonexistent month/day/etc.
var Time = function(der) {
  this._der = der;
  this._year = null;
  this._month = null;
  this._hour = null;
  this._minute = null;
  this._second = null;
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
      this._minute = min1 * 10 + min2;
      
      var s1 = this._validateDigit(contents.readByte());
      var s2 = this._validateDigit(contents.readByte());
      this._second = s1 * 10 + s2;

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

  toString: function() {
    return (new Date(Date.UTC(this._year, this._month + 1,
                              this._day, this._hour, this._minute,
                              this._second))).toString();
  },
};

var Validity = function(der) {
  this._der = der;
  this._notBefore = null;
  this._notAfter = null;
  this._displayFields = [
    new DisplayField("_notBefore", "notBefore", false),
    new DisplayField("_notAfter", "notAfter", false),
  ];
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
      this._notBefore = new Time(
        contents.readTLVChoice([UTCTime, GeneralizedTime]));
      this._notBefore.parse();
    } catch (e) {
      console.log("error parsing notBefore");
      throw e;
    }
    try {
      this._notAfter = new Time(
        contents.readTLVChoice([UTCTime, GeneralizedTime]));
      this._notAfter.parse();
    } catch (e) {
      console.log("error parsing notAfter");
      throw e;
    }
    contents.assertAtEnd();
    this._der.assertAtEnd();
  },
};

var RSAPublicKey = function(der) {
  this._der = der;
  this._modulus = null;
  this._publicExponent = null;
  this._displayFields = [
    new DisplayField("_modulus", "modulus", false),
    new DisplayField("_publicExponent", "publicExponent", false),
  ];
};

RSAPublicKey.prototype = {
  parse: function() {
    var contents;
    try {
      contents = this._der.readSEQUENCE();
    } catch (e) {
      console.log("error parsing RSAPublicKey");
      throw e;
    }
    try {
      this._modulus = new ByteArray(contents.readINTEGER(), "");
    } catch (e) {
      console.log("error parsing modulus");
      throw e;
    }
    try {
      this._publicExponent = new ByteArray(contents.readINTEGER(), "");
    } catch (e) {
      console.log("error parsing publicExponent");
      throw e;
    }
    contents.assertAtEnd();
    this._der.assertAtEnd();
  },
};

var SubjectPublicKeyInfo = function(der) {
  this._der = der;
  this._algorithm = null;
  this._subjectPublicKey = null;
  this._displayFields = [
    new DisplayField("_algorithm", "algorithm", true),
    new DisplayField("_subjectPublicKey", "subjectPublicKey", true),
  ];
};

SubjectPublicKeyInfo.prototype = {
  parse: function() {
    var contents;
    try {
      contents = this._der.readSEQUENCE();
    } catch (e) {
      console.log("error parsing SubjectPublicKeyInfo");
      throw e;
    }
    try {
      this._algorithm = new AlgorithmIdentifier(contents.readTLV());
      this._algorithm.parse();
    } catch (e) {
      console.log("error parsing algorithm");
      throw e;
    }
    try {
      var subjectPublicKeyBytes = contents.readBITSTRING();
      if (this._algorithm._oid.toString() == "rsaEncryption") {
        this._subjectPublicKey = new RSAPublicKey(
          new der(subjectPublicKeyBytes));
        this._subjectPublicKey.parse();
      } else {
        this._subjectPublicKey = new ByteArray(subjectPublicKeyBytes, "");
      }
    } catch (e) {
      console.log("error parsing subjectPublicKey");
      throw e;
    }
    contents.assertAtEnd();
    this._der.assertAtEnd();
  },
};

var BasicConstraints = function(der) {
  this._der = der;
  this._cA = null;
  this._pathLenConstraint = null;
  this._displayFields = [
    new DisplayField("_cA", "cA", false),
    new DisplayField("_pathLenConstraint", "pathLenConstraint", false),
  ];
};

BasicConstraints.prototype = {
  parse: function() {
    var contents;
    try {
      contents = this._der.readSEQUENCE();
    } catch (e) {
      console.log("error parsing BasicConstraints");
      throw e;
    }
    try {
      // TODO: check for explicit encoding of DEFAULT FALSE
      if (contents.peekTag(BOOLEAN)) {
        var cAValue = contents.readBOOLEAN();
        if (cAValue == 0xff) {
          this._cA = true;
        } else if (cAValue == 0x00) {
          this._cA = false;
        } else {
          throw ERROR_LIBRARY_FAILURE;
        }
      } else {
        this._cA = false;
      }
    } catch (e) {
      console.log("error parsing cA");
      throw e;
    }
    try {
      if (contents.peekTag(INTEGER)) {
        var pathLenConstraintBytes = contents.readINTEGER();
        if (pathLenConstraintBytes.length != 1) {
          throw ERROR_UNSUPPORTED_EXTENSION_VALUE;
        }
        this._pathLenConstraint = pathLenConstraintBytes[0];
      }
    } catch (e) {
      console.log("error parsing pathLenConstraint");
      throw e;
    }
    contents.assertAtEnd();
    this._der.assertAtEnd();
  },
};

var SubjectKeyIdentifier = function(der) {
  this._der = der;
  this._keyIdentifier = null;
  this._displayFields = [
    new DisplayField("_keyIdentifier", "keyIdentifier", false),
  ];
};

SubjectKeyIdentifier.prototype = {
  parse: function() {
    try {
      this._keyIdentifier = new ByteArray(this._der.readOCTETSTRING(), ":");
    } catch (e) {
      console.log("error parsing keyIdentifier");
      throw e;
    }
    this._der.assertAtEnd();
  },
};

var KnownExtensions = {
  "id-ce-basicConstraints": BasicConstraints,
  "id-ce-subjectKeyIdentifier": SubjectKeyIdentifier,
};

var Extensions = function(der) {
  this._der = der;
  this._extensions = null;
  this._displayFields = [
    new DisplayField("_extensions", "extension", true),
  ];
};

Extensions.prototype = {
  parse: function() {
    var contents;
    try {
      contents = this._der.readSEQUENCE();
    } catch (e) {
      console.log("error parsing Extensions");
      throw e;
    }
    try {
      while (!contents.atEnd()) {
        this._extensions = [];
        while (!contents.atEnd()) {
          var extension = new Extension(contents.readTLV());
          extension.parse();
          this._extensions.push(extension);
        }
      }
    } catch (e) {
      console.log("error parsing Extensions");
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
  this._displayFields = [
    new DisplayField("_oid", "type", false),
    new DisplayField("_critical", "critical", false),
    new DisplayField("_value", "value", true),
  ];
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
        var criticalValue = contents.readBOOLEAN();
        if (criticalValue == 0xff) {
          this._critical = true;
        } else if (criticalValue == 0x00) {
          this._critical = false;
        } else {
          throw ERROR_LIBRARY_FAILURE;
        }
      } else {
        this._critical = false;
      }
    } catch (e) {
      console.log("error parsing critical");
      throw e;
    }
    try {
      this._value = contents.readOCTETSTRING();
      if (this._oid.toString() in KnownExtensions) {
        var extensionType = KnownExtensions[this._oid.toString()];
        this._value = new extensionType(new der(this._value));
        this._value.parse();
      } else {
        this._displayFields[2]._recurse = false; // TODO: eh...
      }
    } catch (e) {
      console.log("error parsing extnValue");
      throw e;
    }
    contents.assertAtEnd();
    this._der.assertAtEnd();
  },
};

try {
  exports.Certificate = Certificate;
} catch (e) {
}

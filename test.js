var lintx509 = require("./lintx509.js");
var atob = require("atob");

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
var cert = new lintx509.Certificate(bytes);
cert.parse();
console.log(cert._tbsCertificate._issuer._rdns[0]._avas[0]._value.toString());
console.log(cert._tbsCertificate._subject._rdns[0]._avas[0]._value.toString());

pem = "-----BEGIN CERTIFICATE-----\n" +
"MIIFWDCCA0CgAwIBAgIQUHBrzdgT/BtOOzNy0hFIjTANBgkqhkiG9w0BAQsFADBG\n" +
"MQswCQYDVQQGEwJDTjEaMBgGA1UEChMRV29TaWduIENBIExpbWl0ZWQxGzAZBgNV\n" +
"BAMMEkNBIOayg+mAmuagueivgeS5pjAeFw0wOTA4MDgwMTAwMDFaFw0zOTA4MDgw\n" +
"MTAwMDFaMEYxCzAJBgNVBAYTAkNOMRowGAYDVQQKExFXb1NpZ24gQ0EgTGltaXRl\n" +
"ZDEbMBkGA1UEAwwSQ0Eg5rKD6YCa5qC56K+B5LmmMIICIjANBgkqhkiG9w0BAQEF\n" +
"AAOCAg8AMIICCgKCAgEA0EkhHiX8h8EqwqzbdoYGTufQdDTc7WU1/FDWiD+k8H/r\n" +
"D195L4mx/bxjWDeTmzj4t1up+thxx7S8gJeNbEvxUNUqKaqoGXqW5pWOdO2XCld1\n" +
"9AXbbQs5uQF/qvbW2mzmBeCkTVL829B0txGMe41P/4eDrv8FAxNXUDf+jJZSEExf\n" +
"v5RxadmWPgxDT74wwJ85dE8GRV2j1lY5aAfMh09Qd5Nx2UQIsYo06Yms25tO4dnk\n" +
"UkWMLhQfkWsZHWgpLFbE4h4TV2TwYeO5Ed+w4VegG63XX9Gv2ystP9Bojg/qnw+L\n" +
"NVgbExz03jWhCl3W6t8Sb8D7aQdGctyB9gQjF+BNdeFyb7Ao65vh4YOhn0pdr8yb\n" +
"+gIgthhid5E7o9Vlrdx8kHccREGkSovrlXLp9glk3Kgtn3R46MGiCWOc76DbT52V\n" +
"qyBPt7D3h1ymoOQ3OMdc4zUPLK2jgKLsLl3Az+2LBcLmc272idX10kaO6m1jGx6K\n" +
"yX2m+Jzr5dVjhU1zZmkR/sgO9MHHZklTfuQZa/HpelmjbX7FF+Ynxu8b22/8DU0G\n" +
"AbQOXDBGVWCvOGU6yke6rCzMRh+yRpY/8+0mBe53oWprfi1tWFxK1I5nuPHa1UaK\n" +
"J/kR8slC/k7e3x9cxKSGhxYzoacXGKUN5AXlK8IrC6KVkLn9YDxOiT7nnO4fuwEC\n" +
"AwEAAaNCMEAwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0O\n" +
"BBYEFOBNv9ybQV0T6GTwp+kVpOGBwboxMA0GCSqGSIb3DQEBCwUAA4ICAQBqinA4\n" +
"WbbaixjIvirTthnVZil6Xc1bL3McJk6jfW+rtylNpumlEYOnOXOvEESS5iVdT2H6\n" +
"yAa+Tkvv/vMx/sZ8cApBWNromUuWyXi8mHwCKe0JgOYKOoICKuLJL8hWGSbueBwj\n" +
"/feTZU7n85iYr83d2Z5AiDEoOqsuC7CsDCT6eiaY8xJhEPRdF/d+4niXVOKM6Cm6\n" +
"jBAyvd0zaziGfjk9DgNyp115j0WKWa5bIW4xRtVZjc8VX90xJc/bYNaBRHIpAlf2\n" +
"ltTW/+op2znFuCyKGo3Oy+dCMYYFaA6eFN0AkLppRQjbbpCBhqcqBT/mhDn4t/lX\n" +
"X0ykeVoQDF7Va/81XwVRHmyjdanPUIPTfPRm94KNPQx96N97qA4bLJyuQHCH2u2n\n" +
"FoJavjVsIE4iYdm8UXrNemHcSxH5/mc0zy4EZmFcV5cjjPOGG0jfKq+nwf/Yjj4D\n" +
"u9gqsPoUJbJRa4ZDhS4HIxaAjUz7tGM7zMN07RujHv41D198HRaG9Q7DlfEvr10l\n" +
"O1Hm13ZBONFLAzkopR6RctR9q5czxNM+4Gm2KHmgCY0c0f9BckgG/Jou5yD5m6Le\n" +
"ie2uPAmvylezkolwQOQvT8Jwg0DXJCxr5wkf09XHwQj02w47HAcLQxGEIYbpgNR1\n" +
"2KvxAmLBsX5VYc8T1yaw15zLKYs4SgsOkI26oQ==\n" +
"-----END CERTIFICATE-----\n";
bytes = pemToBytes(pem);
cert = new lintx509.Certificate(bytes);
cert.parse();
console.log(cert._tbsCertificate._issuer._rdns[2]._avas[0]._value.toString());

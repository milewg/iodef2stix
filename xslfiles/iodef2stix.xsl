<?xml version="1.0" encoding="UTF-8"?>
<xsl:transform xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0"
  xmlns:iodef="urn:ietf:params:xml:ns:iodef-2.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xmlns:cybox="http://cybox.mitre.org/cybox-2"
  xmlns:cyboxCommon="http://cybox.mitre.org/common-2"
  xmlns:cyboxVocabs="http://cybox.mitre.org/default_vocabularies-2"
  xmlns:AddressObj="http://cybox.mitre.org/objects#AddressObject-2"
  xmlns:DomainNameObj="http://cybox.mitre.org/objects#DomainNameObject-1"  
  xmlns:ArtifactObj="http://cybox.mitre.org/objects#ArtifactObject-2"
  xmlns:EmailMessageObj="http://cybox.mitre.org/objects#EmailMessageObject-2"
  xmlns:FileObj="http://cybox.mitre.org/objects#FileObject-2"
  xmlns:PortObj="http://cybox.mitre.org/objects#PortObject-2"
  xmlns:ProductObj="http://cybox.mitre.org/objects#ProductObject-2"
  xmlns:URIObj="http://cybox.mitre.org/objects#URIObject-2"
  xmlns:WinRegistryKeyObj="http://cybox.mitre.org/objects#WinRegistryKeyObject-2"
  xmlns:X509CertificateObj="http://cybox.mitre.org/objects#X509CertificateObject-2"
  xmlns:CustomObj="http://cybox.mitre.org/objects#CustomObject-1"
  xmlns:maecPackage="http://maec.mitre.org/XMLSchema/maec-package-2"
  xmlns:maecBundle="http://maec.mitre.org/XMLSchema/maec-bundle-4"
  xmlns:maecVocabs="http://maec.mitre.org/default_vocabularies-1"
  xmlns:maecExtension="http://stix.mitre.org/extensions/Malware#MAEC4.1-1"
  xmlns:stix="http://stix.mitre.org/stix-1"
  xmlns:stixCommon="http://stix.mitre.org/common-1"
  xmlns:stixVocabs="http://stix.mitre.org/default_vocabularies-1"
  xmlns:marking="http://data-marking.mitre.org/Marking-1"
  xmlns:tlpMarking="http://data-marking.mitre.org/extensions/MarkingStructure#TLP-1"
  xmlns:stix-ciqaddress="http://stix.mitre.org/extensions/Address#CIQAddress3.0-1"
  xmlns:stix-ciqidentity="http://stix.mitre.org/extensions/Identity#CIQIdentity3.0-1"
  xmlns:indicator="http://stix.mitre.org/Indicator-2"
  xmlns:snortTM="http://stix.mitre.org/extensions/TestMechanism#Snort-1"
  xmlns:yaraTM="http://stix.mitre.org/extensions/TestMechanism#YARA-1"
  xmlns:openiocTM="http://stix.mitre.org/extensions/TestMechanism#OpenIOC2010-1"
  xmlns:ttp="http://stix.mitre.org/TTP-1"
  xmlns:et="http://stix.mitre.org/ExploitTarget-1"
  xmlns:incident="http://stix.mitre.org/Incident-1"
  xmlns:coa="http://stix.mitre.org/CourseOfAction-1"
  xmlns:campaign="http://stix.mitre.org/Campaign-1"
  xmlns:ta="http://stix.mitre.org/ThreatActor-1"
  xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
  
  xsi:schemaLocation="
   http://www.iana.org/assignments/xml-registry/schema/iodef-2.0.xsd
   http://cybox.mitre.org/common-2
   http://cybox.mitre.org/XMLSchema/common/2.1/cybox_common.xsd
   http://cybox.mitre.org/default_vocabularies-2
   http://cybox.mitre.org/XMLSchema/default_vocabularies/2.1/cybox_default_vocabularies.xsd
   http://cybox.mitre.org/objects#AddressObject-2
   http://cybox.mitre.org/XMLSchema/objects/Address/2.1/Address_Object.xsd
   http://cybox.mitre.org/objects#ArtifactObject-2
   http://cybox.mitre.org/XMLSchema/objects/Artifact/2.1/Artifact_Object.xsd
   http://cybox.mitre.org/objects#EmailMessageObject-2
   http://cybox.mitre.org/XMLSchema/objects/Email_Message/2.1/Email_Message_Object.xsd
   http://cybox.mitre.org/objects#FileObject-2
   http://cybox.mitre.org/XMLSchema/objects/File/2.1/File_Object.xsd
   http://cybox.mitre.org/objects#PortObject-2
   http://cybox.mitre.org/XMLSchema/objects/Port/2.1/Port_Object.xsd
   http://cybox.mitre.org/objects#ProductObject-2
   https://cybox.mitre.org/XMLSchema/objects/Product/2.1/Product_Object.xsd
   http://cybox.mitre.org/objects#URIObject-2
   http://cybox.mitre.org/XMLSchema/objects/URI/2.1/URI_Object.xsd
   http://cybox.mitre.org/objects#WinRegistryKeyObject-2
   http://cybox.mitre.org/XMLSchema/objects/Win_Registry_Key/2.1/Win_Registry_Key_Object.xsd
   http://maec.mitre.org/XMLSchema/maec-package-2
   http://maec.mitre.org/language/version4.1/maec_package_schema.xsd
   http://maec.mitre.org/XMLSchema/maec-bundle-4
   http://maec.mitre.org/language/version4.1/maec_bundle_schema.xsd
   http://maec.mitre.org/default_vocabularies-1
   http://maec.mitre.org/language/version4.1/maec_default_vocabularies.xsd
   http://stix.mitre.org/extensions/Malware#MAEC4.1-1
   http://stix.mitre.org/XMLSchema/extensions/malware/maec_4.1/1.0.1/maec_4.1_malware.xsd
   http://stix.mitre.org/stix-1
   http://stix.mitre.org/XMLSchema/core/1.1.1/stix_core.xsd
   http://stix.mitre.org/common-1
   http://stix.mitre.org/XMLSchema/common/1.1.1/stix_common.xsd
   http://stix.mitre.org/default_vocabularies-1
   http://stix.mitre.org/XMLSchema/default_vocabularies/1.1.1/stix_default_vocabularies.xsd
   http://data-marking.mitre.org/Marking-1
   http://stix.mitre.org/XMLSchema/data_marking/1.1.1/data_marking.xsd
   http://data-marking.mitre.org/extensions/MarkingStructure#TLP-1
   http://stix.mitre.org/XMLSchema/extensions/marking/tlp/1.1.1/tlp_marking.xsd
   http://stix.mitre.org/extensions/Address#CIQAddress3.0-1
   http://stix.mitre.org/XMLSchema/extensions/address/ciq_3.0/1.1.1/ciq_3.0_address.xsd
   http://stix.mitre.org/extensions/Identity#CIQIdentity3.0-1
   http://stix.mitre.org/XMLSchema/extensions/identity/ciq_3.0/1.1.1/ciq_3.0_identity.xsd
   http://stix.mitre.org/Indicator-2
   http://stix.mitre.org/XMLSchema/indicator/2.1.1/indicator.xsd
   http://stix.mitre.org/extensions/TestMechanism#Snort-1
   http://stix.mitre.org/XMLSchema/extensions/test_mechanism/snort/1.1.1/snort_test_mechanism.xsd
   http://stix.mitre.org/extensions/TestMechanism#YARA-1
   http://stix.mitre.org/XMLSchema/extensions/test_mechanism/yara/1.1.1/yara_test_mechanism.xsd
   http://stix.mitre.org/extensions/TestMechanism#OpenIOC2010-1
   http://stix.mitre.org/XMLSchema/extensions/test_mechanism/open_ioc_2010/1.1.1/open_ioc_2010_test_mechanism.xsd
   http://stix.mitre.org/TTP-1
   http://stix.mitre.org/XMLSchema/ttp/1.1.1/ttp.xsd
   http://stix.mitre.org/ExploitTarget-1
   http://stix.mitre.org/XMLSchema/exploit_target/1.1.1/exploit_target.xsd
   http://stix.mitre.org/Incident-1
   http://stix.mitre.org/XMLSchema/incident/1.1.1/incident.xsd
   http://stix.mitre.org/COA-1
   http://stix.mitre.org/XMLSchema/course_of_action/1.1.1/course_of_action.xsd
   http://stix.mitre.org/Campaign-1
   http://stix.mitre.org/XMLSchema/campaign/1.1.1/campaign.xsd
   http://stix.mitre.org/ThreatActor-1
   http://stix.mitre.org/XMLSchema/threat_actor/1.1.1/threat_actor.xsd"
  >
  <xsl:output method="xml" indent="yes"/>

  <xsl:template match="iodef:IODEF-Document">
    <stix:STIX_Package>
	<xsl:apply-templates select="iodef:Incident"/>
    </stix:STIX_Package>
  </xsl:template>

  <xsl:template match="iodef:Incident">
    <stix:Report>
      <stix:Header>
	<stix:Title></stix:Title>
	<stix:Package-intent>
	  <xsl:value-of select="@purpose" />
	</stix:Package-intent>
      </stix:Header>
      <!-- Incident node -->
      <stix:Incidents>
	<stix:Incident id="{translate(translate(translate(iodef:IncidentID,'&#xA;',''),'&#9;',''),' ','')}" URL="{iodef:IncidentID/@name}">
	  <xsl:apply-templates select="iodef:Description" mode="incident"/>
	  <xsl:apply-templates select="iodef:Contact"/>
	  <xsl:apply-templates select="iodef:Assessment"/>
	  <xsl:apply-templates select="iodef:RelatedActivity"/>
	  <incident:Time>
	    <xsl:apply-templates select="iodef:DetectTime"/>
	    <xsl:apply-templates select="iodef:StartTime"/>
	    <xsl:apply-templates select="iodef:EndTime"/>
	    <xsl:apply-templates select="iodef:RecoveryTime"/>
	    <xsl:apply-templates select="iodef:ReportTime"/>
	    <xsl:apply-templates select="iodef:GenerationTime"/>
	  </incident:Time>
	  <xsl:apply-templates select="@restriction" mode="incident"/>
	</stix:Incident>
      </stix:Incidents>

      <xsl:apply-templates select="iodef:IndicatorData"/>

      <xsl:if test="iodef:EventData">
	<stix:Observables>
	  <xsl:apply-templates select="iodef:EventData"/>
	</stix:Observables>
      </xsl:if>
      
      <xsl:if test="iodef:RelatedActivity/iodef:Campaign">
	<stix:Campaigns>
	  <xsl:apply-templates select="iodef:RelatedActivity/iodef:Campaign" />
	</stix:Campaigns>
      </xsl:if>

      <xsl:if test="iodef:RelatedActivity/iodef:ThreatActor">
	<stix:Threat_Actors>
	  <xsl:apply-templates select="iodef:RelatedActivity/iodef:ThreatActor"/>
	</stix:Threat_Actors>
      </xsl:if>
      
    </stix:Report>
  </xsl:template>

  <!-- Incident Status -->
  <xsl:template match="@status">
    <incident:Status>
      <xsl:value-of select="@status" />
    </incident:Status>
  </xsl:template>
  
  <!-- Incident Description -->
  <xsl:template match="iodef:Description" mode="incident">
    <incident:Description>
      <xsl:value-of select="." />
    </incident:Description>
  </xsl:template>

  <!-- Incident Contact -->
  <xsl:template match="iodef:Contact">
    <incident:Contact>
      <stixCommon:Role vocab_name="{@type}">
	<xsl:value-of select="@role" />
      </stixCommon:Role>
      <xsl:apply-templates select="iodef:Description" mode="contact" />
      <xsl:apply-templates select="iodef:ContactName" />
      <xsl:apply-templates select="iodef:Email" />
    </incident:Contact>
  </xsl:template>

  <xsl:template match="iodef:Description" mode="contact">
    <stixCommon:Description>
      <xsl:value-of select="."/>
    </stixCommon:Description>
  </xsl:template>

  <xsl:template match="iodef:ContactName">
    <stixCommon:Identity>
      <stixCommon:Name>
	<xsl:value-of select="."/>
      </stixCommon:Name>
    </stixCommon:Identity>
  </xsl:template>

  <xsl:template match="iodef:Email">
    <!-- pack "Email" into 'Description node' -->
    <stixCommon:Description>
      <EmailTo>
	<xsl:value-of select="."/>
      </EmailTo>
    </stixCommon:Description>
  </xsl:template>

  <!-- Incident Assessment -->
  <xsl:template match="iodef:Assessment">
    <xsl:apply-templates select="@occurrence" mode="assessment"/>
    <xsl:if test="iodef:SystemImpact | iodef:BusinessImpact">
      <incident:Impact_Assessment>
	<xsl:apply-templates select="iodef:SystemImpact"/>
	<xsl:apply-templates select="iodef:BusinessImpact"/>
      </incident:Impact_Assessment>
    </xsl:if>
    <xsl:apply-templates select="iodef:Confidence" mode="assessment"/>
  </xsl:template>

  <xsl:template match="@occurrence" mode="assessment">
    <incident:Status>
      <xsl:value-of select="."/>
    </incident:Status>
  </xsl:template>

  <xsl:template match="iodef:SystemImpact">
      <incident:Impact_Qualification vocab_name="{@type}">
	<xsl:value-of select="@severity"/>
      </incident:Impact_Qualification>
      <xsl:apply-templates select="iodef:Description" mode="assessment"/>      
  </xsl:template>

  <xsl:template match="iodef:BusinessImpact">
    <incident:Total_Loss_Estimation>
      <incident:Actual_Total_Loss_Estimation>
	<xsl:attribute name="amount">
	  <xsl:value-of select="@type"/>
	</xsl:attribute>
      </incident:Actual_Total_Loss_Estimation>
    </incident:Total_Loss_Estimation>
  </xsl:template>
  
  <xsl:template match="iodef:Description" mode="assessment">
    <incident:Effects>
      <incident:Effect>
	<!--
	<xsl:attribute name="vocab_name">
	  <xsl:value-of select="../../@occurrence"/>
	  </xsl:attribute>
	  -->
	<xsl:value-of select="."/>
      </incident:Effect>
    </incident:Effects>
  </xsl:template>

  
  <xsl:template match="iodef:Confidence" mode="assessment">
    <incident:Confidence>
      <stixCommon:Value>
	<xsl:value-of select="@rating"/>
      </stixCommon:Value>
    </incident:Confidence>
  </xsl:template>

  <xsl:template match="iodef:RelatedActivity">
    <incident:Related_Incidents>
      <xsl:apply-templates select="iodef:URL" mode="relatedactivity"/>
    </incident:Related_Incidents>
  </xsl:template>
  
  <xsl:template match="iodef:URL" mode="relatedactivity">
    <stixCommon:Related_Incident>
      <stixCommon:InformationSource>
	<stixCommon:Description structuring_format="URL">
    	    <xsl:value-of select="." />
	  </stixCommon:Description>
      </stixCommon:InformationSource>
    </stixCommon:Related_Incident>
  </xsl:template>

  <!-- Incident DetectTime -->
  <xsl:template match="iodef:DetectTime">
    <incident:Incident_Discovery>
      <xsl:value-of select="."/>  <!-- 発見時刻 -->
    </incident:Incident_Discovery>
  </xsl:template>
  
  <!-- Incident StartTime -->
  <xsl:template match="iodef:StartTime">
    <incident:Initial_Compromise>
      <xsl:value-of select="."/>  <!-- 侵害発生時刻 -->
    </incident:Initial_Compromise>
  </xsl:template>

  <!-- Incident EndTime -->
  <xsl:template match="iodef:EndTime">
    <incident:Containment_Achieved>
      <xsl:value-of select="."/>  <!-- 対応完了時刻 -->
    </incident:Containment_Achieved>
  </xsl:template>

  <!-- Incident RecoveryTime -->
  <xsl:template match="iodef:RecoveryTime">
    <incident:Restoration_Achieved>
      <xsl:value-of select="."/>  <!-- 復旧完了時刻 -->	  
    </incident:Restoration_Achieved>
  </xsl:template>

  <!-- Incident ReportTime -->
  <xsl:template match="iodef:ReportTime">
    <incident:Incident_Reported>
      <xsl:value-of select="."/>  <!-- 報告時刻 -->
    </incident:Incident_Reported>
  </xsl:template>

  <!-- Incident GenerationTime -->
  <xsl:template match="iodef:GenerationTime">
    <incident:FirstMalicious_Action>
      <xsl:value-of select="."/>  <!-- 生成時刻 -->
    </incident:FirstMalicious_Action>
  </xsl:template>

  
  <xsl:template match="iodef:EventData">
    <cybox:Observable>
      <cybox:Object>
	<cybox:Properties xsi:type="CustomObj:CustomObjectType" CustomObj:custom_name="NICT_iodefEventdata">
<!--	  <xsl:copy-of select="."/>  -->
	  <xsl:apply-templates select="." mode="copy"/>
	</cybox:Properties>
      </cybox:Object>
    </cybox:Observable>
  </xsl:template>


  <xsl:template match="iodef:IndicatorData">
    <stix:Indicators>
      <xsl:apply-templates select="iodef:Indicator" mode="indicatordata"/>
    </stix:Indicators>
  </xsl:template>

  <xsl:template match="iodef:Indicator" mode="indicatordata">
    <stix:Indicator>
      <xsl:attribute name="version">
	<xsl:value-of select="iodef:IndicatorID/@version"/>
      </xsl:attribute>
      <xsl:attribute name="id">
	<xsl:value-of select="translate(translate(translate(iodef:IndicatorID,'&#xA;',''),'&#9;',''),' ','')"/>	
      </xsl:attribute>
      <indicator:Alternative_ID>
	<xsl:value-of select="iodef:IndicatorID/@name"/>
      </indicator:Alternative_ID>
      <xsl:apply-templates select="iodef:Description" mode="indicatordata"/>
      <xsl:if test="iodef:StartTime | iodef:EndTime">      
	<indicator:Valid_Time_Position>
	  <xsl:apply-templates select="iodef:StartTime" mode="indicatordata"/>
	  <xsl:apply-templates select="iodef:EndTime" mode="indicatordata"/>
	</indicator:Valid_Time_Position>
      </xsl:if>	
      <xsl:apply-templates select="iodef:Observable"/>
      <xsl:apply-templates select="iodef:IndicatorExpression"/>
    </stix:Indicator>
  </xsl:template>

  <xsl:template match="iodef:Description" mode="indicatordata">
    <indicator:Description>
      <xsl:value-of select="."/>
    </indicator:Description>
  </xsl:template>

  <xsl:template match="iodef:StartTime" mode="indicatordata">
      <stixCommon:Start_Time>
	<xsl:value-of select="."/>
      </stixCommon:Start_Time>
  </xsl:template>
  
  <xsl:template match="iodef:EndTime" mode="indicatordata">
      <stixCommon:End_Time>
	<xsl:value-of select="."/>
      </stixCommon:End_Time>
  </xsl:template>

  <xsl:template match="iodef:IndicatorExpression">
    <cybox:Observable>  <!-- 0121 21:45 -->
      <cybox:Observable_Composition operator="{@operator}">
	<xsl:apply-templates select="iodef:IndicatorExpression"/>
	<xsl:apply-templates select="iodef:Observable"/>
	<xsl:apply-templates select="iodef:ObservableReference"/>
      </cybox:Observable_Composition>
    </cybox:Observable>
  </xsl:template>
  
  <xsl:template match="iodef:ObservableReference">
    <cybox:Observable>
      <xsl:apply-templates select="@uid-ref"/>
      <xsl:apply-templates select="@euid-ref"/>
    </cybox:Observable>
  </xsl:template>
  
  <xsl:template match="@uid-ref">
      <xsl:attribute name="idref">
	<xsl:value-of select="."/>
      </xsl:attribute>
      <cybox:Description>uid-ref</cybox:Description>
  </xsl:template>
  
  <xsl:template match="@euid-ref">
      <xsl:attribute name="idref">
	<xsl:value-of select="."/>
      </xsl:attribute>
      <cybox:Description>euid-ref</cybox:Description>
  </xsl:template>
  
  <xsl:template match="iodef:Observable">         <!-- Convert iodef Observable to cybox Observable. -->
    <xsl:apply-templates select="iodef:Address" mode="observable"/>
    <xsl:apply-templates select="iodef:DomainData" mode="observable"/>
    <xsl:apply-templates select="iodef:EmailData" mode="observable"/>
    <xsl:apply-templates select="iodef:WindowsRegistryKeysModified" mode="observable"/>
    <xsl:apply-templates select="iodef:FileData" mode="observable"/>
    <xsl:apply-templates select="iodef:CertificateData" mode="observable"/>
    <!--
	System
        Service
        RegistryHandle
	RecordData
	EventData
	Incident
	Exprectation
	Reference
	Assessment
	DetectionPattern
	HistoryItem
	AdditionalData
    -->
    <xsl:apply-templates select="iodef:BulkObservable" mode="observable"/>
  </xsl:template>

  <xsl:template match="iodef:System" mode="observable">
  </xsl:template>
  
  <xsl:template match="iodef:Address" mode="observable">
    <cybox:Observable>
      <xsl:attribute name="id">
	<xsl:value-of select="@observable-id"/>
      </xsl:attribute>
      <cybox:Object>
	<cybox:Properties xsi:type="AddressObj:AddressObjectType" category="{@category}">
	  <AddressObj:Address_Value>
	    <xsl:value-of select="."/>
	  </AddressObj:Address_Value>
	</cybox:Properties>
      </cybox:Object>
    </cybox:Observable>
  </xsl:template>
  
  <xsl:template match="iodef:DomainData" mode="observable">
    <cybox:Observable>
      <cybox:Object>
	<cybox:Properties xsi:type="DomainNameObj:DomainNameObjectType" type="{@domain-status}">
	  <DomainNameObj:Value>
	    <xsl:value-of select="."/>
	  </DomainNameObj:Value>
	</cybox:Properties>
      </cybox:Object>
    </cybox:Observable>
  </xsl:template>
  
  <xsl:template match="iodef:EmailData" mode="observable">
    <cybox:Observable>
      <cybox:Object>
	<cybox:Properties xsi:type="EmailMessageObj:EmailMessageObjectType">
	  <EmailMessageObj:Header>
	    <xsl:value-of select="iodef:EmailHeaders"/>
	  </EmailMessageObj:Header>
	  <EmailMessageObj:Raw_Header>
	    <xsl:value-of select="iodef:EmailHeaderField"/>
	  </EmailMessageObj:Raw_Header>
	  <EmailMessageObj:Raw_Body>
	    <xsl:value-of select="iodef:EmailBody"/>
	  </EmailMessageObj:Raw_Body>
	</cybox:Properties>
      </cybox:Object>
    </cybox:Observable>
  </xsl:template>


  <xsl:template match="iodef:WindowsRegistryKeysModified" mode="observable">
    <cybox:Observable>
      <cybox:Object>
	<cybox:Properties xsi:type="CustomObj:CustomObjectType" CustomObj:custom_name="NICT_WinRegKeys">
<!--	  <xsl:copy-of select="."/>  -->
          <xsl:apply-templates select="." mode="copy"/>
	</cybox:Properties>
      </cybox:Object>
    </cybox:Observable>
  </xsl:template>

  
  <xsl:template match="iodef:FileData" mode="observable">
    <cybox:Observable>
      <xsl:apply-templates select="@observable-id"/>
      <cybox:Object>
	<cybox:Properties xsi:type="FileObj:FileObjectType">
	  <xsl:apply-templates select="iodef:File/iodef:FileName"/>
	  <xsl:apply-templates select="iodef:File/iodef:FileSize"/>
	  <xsl:apply-templates select="iodef:File/iodef:HashData"/>
	  <xsl:apply-templates select="iodef:File/iodef:SignatureData"/>
	</cybox:Properties>
      </cybox:Object>
    </cybox:Observable>
  </xsl:template>

  <xsl:template match="@observable-id">
    <xsl:attribute name="id">
      <xsl:value-of select="."/>
    </xsl:attribute>
  </xsl:template>
  
  <xsl:template match="iodef:File/iodef:FileName">
    <FileObj:File_Name>
      <xsl:value-of select="."/>
    </FileObj:File_Name>
  </xsl:template>
  <xsl:template match="iodef:File/iodef:FileSize">
    <FileObj:Size_In_Bytes>
      <xsl:value-of select="."/>
    </FileObj:Size_In_Bytes>
  </xsl:template>
  
  <xsl:template match="iodef:File/iodef:HashData">
    <FileObj:Hashes>
      <cyboxCommon:Hash>
	<xsl:apply-templates select="iodef:Hash/ds:DigestMethod"/>
	<xsl:apply-templates select="iodef:Hash/ds:DigestValue"/>
      </cyboxCommon:Hash>
    </FileObj:Hashes>
  </xsl:template>

  <xsl:template match="iodef:Hash/ds:DigestMethod">
    <cyboxCommon:Type>
      <xsl:value-of select="@Algorithm"/>
    </cyboxCommon:Type>
  </xsl:template>

  <xsl:template match="iodef:Hash/ds:DigestValue">
    <cyboxCommon:Simple_Hash_Value>
      <xsl:value-of select="translate(translate(translate(.,'&#xA;',''),'&#9;',''),' ','')"/>
    </cyboxCommon:Simple_Hash_Value>
  </xsl:template>
  
  <xsl:template match="iodef:File/iodef:SignatureData">
    <FileObj:Digital_Signatures>
      <cyboxCommon:DigitalSignature>
	<cyboxCommon:Signature_Description>
	  <xsl:value-of select="ds:Signature"/>
	</cyboxCommon:Signature_Description>
      </cyboxCommon:DigitalSignature>
    </FileObj:Digital_Signatures>
  </xsl:template>
  
  <xsl:template match="iodef:CertificateData" mode="observable">
    <cybox:Observable>
      <cybox:Object>
	<cybox:Properties xsi:type="X509CertificateObj:X509CertificateObjectType">
	  <X509CertificateObj:Raw_Certificate>
<!--	    <xsl:copy-of select="iodef:Certificate/ds:X509Data"/>  -->
	    <xsl:apply-templates select="iodef:Certificate/ds:X509Data" mode="copy"/>
	  </X509CertificateObj:Raw_Certificate>
	</cybox:Properties>
      </cybox:Object>
    </cybox:Observable>
  </xsl:template>
  
  <xsl:template match="iodef:BulkObservable" mode="observable">
    <cybox:Observable>
      <cybox:Object>
	<cybox:Properties xsi:type="NICT_iodefIndicatorBulkObservable">
<!--	  <xsl:copy-of select="."/> -->
	  <xsl:apply-templates select="." mode="copy"/>	  
	</cybox:Properties>
      </cybox:Object>
    </cybox:Observable>
  </xsl:template>                                                          <!-- End of 'Observable' convert.-->

    
  <xsl:template match="iodef:Method">
    <stix:TTPs>
      <xsl:apply-templates select="iodef:TTPs"/>
    </stix:TTPs>
  </xsl:template>

  <xsl:template match="iodef:System">
    <stix:Exploit_Targets>
      <xsl:apply-templates select="iodef:Exploit_Targets"/>
    </stix:Exploit_Targets>
  </xsl:template>


  <xsl:template match="iodef:RelatedActivity/iodef:Campaign">
    <stix:Campaign>
      <xsl:apply-templates select="iodef:CampaignID"/>
      <xsl:apply-templates select="iodef:Description" mode="campaign"/>
    </stix:Campaign>
  </xsl:template>

  <xsl:template match="iodef:CampaignID">
    <xsl:attribute name="id">
      <xsl:value-of select="."/>
    </xsl:attribute>
  </xsl:template>

  <xsl:template match="iodef:Description" mode="campaign">
    <campaign:Description>
      <xsl:value-of select="."/>
    </campaign:Description>
  </xsl:template>
  
  <xsl:template match="iodef:RelatedActivity/iodef:ThreatActor">
    <stix:Threat_Actor>
      <xsl:apply-templates select="iodef:ThreatActorID"/>
      <xsl:apply-templates select="iodef:Description" mode="ta"/>
    </stix:Threat_Actor>
  </xsl:template>

  <xsl:template match="iodef:ThreatActorID">
    <xsl:attribute name="id">
      <xsl:value-of 
	  select="translate(translate(translate(.,'&#xA;',''),'&#9;',''),' ','')"/>
    </xsl:attribute>
  </xsl:template>
  
  <xsl:template match="iodef:Description" mode="ta">
    <ta:Description>
      <xsl:value-of select="."/>
    </ta:Description>
  </xsl:template>

  <xsl:template match="@restriction" mode="incident">
    <incident:Handling>
      <stixCommon:Marking>
	<marking:Controlled_Structure>
	  <xsl:value-of select="."/>
	</marking:Controlled_Structure>
      </stixCommon:Marking>
    </incident:Handling>
  </xsl:template>


  <!-- replacement of copy-of. Don't add xmlns attribute to result. -->
  <xsl:template match="*" mode="copy">
    <xsl:element name="{name()}" namespace="{namespace-uri()}">
      <xsl:apply-templates select="@*|node()" mode="copy" />
    </xsl:element>
  </xsl:template>

  <xsl:template match="@*|text()|comment()" mode="copy">
    <xsl:copy/>
  </xsl:template>

  
</xsl:transform>

<?xml version="1.0" encoding="UTF-8"?>
<xsl:transform xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0"
  xmlns:iodef-2.0="urn:ietf:params:xml:ns:iodef-2.0"
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

  <xsl:template match="stix:Report">
    <iodef:IODEF-Document version="2.00">
      <iodef:Incident>
	<xsl:attribute name="purpose">
	  <xsl:value-of select="stix:Header/stix:Package-intent"/>
	</xsl:attribute>
	<xsl:apply-templates select="stix:Incidents/stix:Incident/incident:Handling"/>
	<xsl:apply-templates select="stix:Incidents"/>

	<xsl:if test="stix:Incidents/stix:Incident/incident:Impact_Assessment | stix:Incidents/stix:Incident/incident:Confidence | stix:Incidents/stix:Incident/incident:Status">
	  <iodef:Assessment>
	    <xsl:apply-templates select="stix:Incidents/stix:Incident/incident:Status"/>
	    <xsl:apply-templates select="stix:Incidents/stix:Incident/incident:Impact_Assessment"/>
	    <xsl:apply-templates select="stix:Incidents/stix:Incident/incident:Confidence"/>
	  </iodef:Assessment>
	</xsl:if>
	
	<xsl:apply-templates select="stix:Observables"/>
	<xsl:apply-templates select="stix:Indicators"/>
	<!--
        <xsl:apply-templates select="stix:Campaigns"/>
   	<xsl:apply-templates select="stix:Thread_Actors"/>
	<xsl:apply-templates select="stix:Header"/>
	<xsl:apply-templates select="stix:TTPs"/>
	<xsl:apply-templates select="stix:COA"/>
	<xsl:apply-templates select="stix:Exploit_Targets"/>
	<xsl:apply-templates select="stix:Reports"/>
	<xsl:apply-templates select="stix:Related_Packages"/>
        -->

	<xsl:if test="stix:Incidents/stix:Incident/incident:Related_Incidents | stix:Campaigns | stix:Threat_Actors">
	  <iodef:RelatedActivity>
	    <xsl:apply-templates select="stix:Incidents/stix:Incident/incident:Related_Incidents"/>
	    <xsl:apply-templates select="stix:Campaigns/stix:Campaign"/>
	    <xsl:apply-templates select="stix:Threat_Actors/stix:Threat_Actor"/>
	  </iodef:RelatedActivity>
	</xsl:if>
      </iodef:Incident>
    </iodef:IODEF-Document>
  </xsl:template>

  <xsl:template match="stix:Incidents">
    <xsl:apply-templates select="stix:Incident"/>
  </xsl:template>

  <xsl:template match="stix:Incident">
    <iodef:IncidentID>
      <xsl:attribute name="name">
	<xsl:value-of select="@URL"/>
      </xsl:attribute>
      <xsl:value-of select="@id"/>
    </iodef:IncidentID>
    
    <xsl:apply-templates select="incident:Description" mode="incident"/>
    <xsl:apply-templates select="incident:Time" mode="incident"/>
<!--  <xsl:apply-templates select="incident:Impact_Assessment" mode="incident"/>     -->
<!--  <xsl:apply-templates select="incident:Status" mode="incident"/>                -->
<!--  <xsl:apply-templates select="incident:Related_Incidents" mode="incident"/>     -->
<!--  <xsl:apply-templates select="incident:Confidence" mode="incident"/>            -->
    <xsl:apply-templates select="incident:Contact" mode="incident"/>
  </xsl:template>

  <xsl:template match="stix:Incidents/stix:Incident/incident:Handling">
    <xsl:attribute name="restriction">
      <xsl:value-of select="stixCommon:Marking/marking:Controlled_Structure"/>
    </xsl:attribute>
  </xsl:template>
  
  <xsl:template match="incident:Description" mode="incident">
    <iodef:Description>
      <xsl:value-of select="."/>
    </iodef:Description>
  </xsl:template>

  <xsl:template match="incident:Time" mode="incident">
    <xsl:apply-templates select="incident:Incident_Discovery"/>
    <xsl:apply-templates select="incident:Initial_Compromise"/>
    <xsl:apply-templates select="incident:Containment_Achieved"/>
    <xsl:apply-templates select="incident:Restoration_Achieved"/>
    <xsl:apply-templates select="incident:Incident_Reported"/>
    <xsl:apply-templates select="incident:FirstMalicious_Action"/>
  </xsl:template>

  <xsl:template match="incident:Initial_Compromise">
    <iodef:StartTime>
      <xsl:value-of select="."/>
    </iodef:StartTime>
  </xsl:template>

  <xsl:template match="incident:Incident_Discovery">
    <iodef:DetectTime>
      <xsl:value-of select="."/>
    </iodef:DetectTime>
  </xsl:template>

  <xsl:template match="incident:Containment_Achieved">
    <iodef:EndTime>
      <xsl:value-of select="."/>
    </iodef:EndTime>
  </xsl:template>
  
  <xsl:template match="incident:Restoration_Achieved">
    <iodef:RecoveryTime>
    <xsl:value-of select="."/>
    </iodef:RecoveryTime>
  </xsl:template>
  
  <xsl:template match="incident:Incident_Reported">
    <iodef:ReportTime>
      <xsl:value-of select="."/>
    </iodef:ReportTime>
  </xsl:template>
  
  <xsl:template match="incident:FirstMalicious_Action">
    <iodef:GenerationTime>
      <xsl:value-of select="."/>
    </iodef:GenerationTime>
  </xsl:template>
  
  <xsl:template match="stix:Incidents/stix:Incident/incident:Impact_Assessment">
    <xsl:apply-templates select="incident:Total_Loss_Estimation"/>
    <xsl:if test="incident:Impact_Qualification | incident:Effects">
      <iodef:SystemImpact>
	<xsl:apply-templates select="incident:Impact_Qualification"/>
	<xsl:apply-templates select="incident:Effects" mode="assessment"/>
      </iodef:SystemImpact>
    </xsl:if>
  </xsl:template>

  <xsl:template match="incident:Total_Loss_Estimation">
    <iodef:BusinessImpact>
      <xsl:attribute name="type">
	<xsl:value-of select="incident:Actual_Total_Loss_Estimation/@amount"/>
      </xsl:attribute>
    </iodef:BusinessImpact>
  </xsl:template>

  <xsl:template match="incident:Impact_Qualification">
    <xsl:attribute name="severity">
      <xsl:value-of select="."/>
    </xsl:attribute>
    <xsl:attribute name="type">
      <xsl:value-of select="@vocab_name"/>
    </xsl:attribute>
<!--	<xsl:apply-templates select="incident:Effects/incident:Effect" mode="assessment"/> -->
  </xsl:template>
  
  <xsl:template match="incident:Effects" mode="assessment">
    <iodef:Description>
        <xsl:value-of select="incident:Effect"/>
    </iodef:Description>
  </xsl:template>

  <xsl:template match="stix:Incidents/stix:Incident/incident:Confidence">
    <iodef:Confidence>
      <xsl:attribute name="rating">
	<xsl:value-of select="stixCommon:Value"/>
      </xsl:attribute>
    </iodef:Confidence>
  </xsl:template>

  <xsl:template match="stix:Incidents/stix:Incident/incident:Status">
    <xsl:attribute name="occurrence">
      <xsl:value-of select="."/>
    </xsl:attribute>
  </xsl:template>
  
  
  <xsl:template match="stix:Incidents/stix:Incident/incident:Related_Incidents">
    <xsl:apply-templates select="stixCommon:Related_Incident"/>
  </xsl:template>


  <xsl:template match="stixCommon:Related_Incident">
    <xsl:apply-templates select="stixCommon:InformationSource" mode="relatedincident"/>  
  </xsl:template>

  <xsl:template match="stixCommon:InformationSource" mode="relatedincident">
    <xsl:if test="stixCommon:Description/@structuring_format='URL'">
      <iodef:URL>
	<xsl:value-of select="stixCommon:Description"/>
      </iodef:URL>
    </xsl:if>
  </xsl:template>


  <xsl:template match="stix:Threat_Actors/stix:Threat_Actor">
    <iodef:ThreatActor>
      <xsl:apply-templates select="@id" mode="ta"/>
      <xsl:apply-templates select="ta:Description"/>
    </iodef:ThreatActor>
  </xsl:template>

  <xsl:template match="stix:Campaigns/stix:Campaign">
    <iodef:Campaign>
      <xsl:apply-templates select="@id" mode="campaign"/>
      <xsl:apply-templates select="campaign:Description"/>
    </iodef:Campaign>
  </xsl:template>
  
  <xsl:template match="@id" mode="ta">
    <iodef:ThreatActorID>
	<xsl:value-of select="."/>
      </iodef:ThreatActorID>
  </xsl:template>
  
  <xsl:template match="@id" mode="campaign">
    <iodef:CampaignID>
	<xsl:value-of select="."/>
    </iodef:CampaignID>
  </xsl:template>

  <xsl:template match="ta:Description">
      <iodef:Description>
	<xsl:value-of select="."/>
      </iodef:Description>
  </xsl:template>
  
  <xsl:template match="campaign:Description">
    <iodef:Description>
      <xsl:value-of select="."/>
    </iodef:Description>
  </xsl:template>

  <xsl:template match="incident:Contact" mode="incident">
    <iodef:Contact>
      <xsl:apply-templates select="stixCommon:Role" mode="contact"/>
      <xsl:apply-templates select="stixCommon:Identity" mode="contact"/>
      <xsl:apply-templates select="stixCommon:Description" mode="contact"/>      
    </iodef:Contact>
  </xsl:template>

  <xsl:template match="stixCommon:Role" mode="contact">
    <xsl:attribute name="type">
      <xsl:value-of select="@vocab_name"/>
    </xsl:attribute>
    <xsl:attribute name="role">
      <xsl:value-of select="."/>
    </xsl:attribute>
  </xsl:template>
  
  <xsl:template match="stixCommon:Identity" mode="contact">
    <iodef:ContactName>
      <xsl:value-of select="stixCommon:Name"/>
    </iodef:ContactName>
  </xsl:template>

  <xsl:template match="stixCommon:Description" mode="contact">
    <iodef:Email>
      <iodef:EmailTo>
	<xsl:value-of select="EmailTo"/>
      </iodef:EmailTo>
    </iodef:Email>
  </xsl:template>

  <xsl:template match="stix:Observables">
     <xsl:apply-templates select="cybox:Observable"/>
  </xsl:template>

  <xsl:template match="stix:Indicators">
    <xsl:apply-templates select="stix:Indicator"/>
  </xsl:template>

  <xsl:template match="stix:Indicator">
    <iodef:IndicatorData>
      <iodef:Indicator>
	<iodef:IndicatorID>
	  <xsl:attribute name="version">
	    <xsl:value-of select="@version"/>
	  </xsl:attribute>
	  <xsl:apply-templates select="indicator:Alternative_ID" mode="indicator"/>
	  <xsl:value-of select="@id"/>	
	</iodef:IndicatorID>
	<xsl:apply-templates select="indicator:Valid_Time_Position" mode="indicator"/>
	<xsl:apply-templates select="indicator:Description" mode="indicator"/>
	<xsl:apply-templates select="cybox:Observable"/>
      </iodef:Indicator>
    </iodef:IndicatorData>
  </xsl:template>

  <xsl:template match="indicator:Alternative_ID" mode="indicator">
    <xsl:attribute name="name">
      <xsl:value-of select="."/>
    </xsl:attribute>
  </xsl:template>

  <xsl:template match="indicator:Valid_Time_Position" mode="indicator">
    <xsl:apply-templates select="stixCommon:Start_Time" mode="indicator"/>
    <xsl:apply-templates select="stixCommon:End_Time" mode="indicator"/>    
  </xsl:template>

  <xsl:template match="stixCommon:Start_Time" mode="indicator">
    <iodef:StartTime>
      <xsl:value-of select="."/>
    </iodef:StartTime>
  </xsl:template>
  
  <xsl:template match="stixCommon:End_Time" mode="indicator">
    <iodef:EndTime>
      <xsl:value-of select="."/>
    </iodef:EndTime>
  </xsl:template>
  
  <xsl:template match="indicator:Description" mode="indicator">
    <iodef:Description>
      <xsl:value-of select="."/>
    </iodef:Description>
  </xsl:template>


  <!-- convert cybox observable to iodef xml. -->
  <xsl:template match="cybox:Observable">
    <xsl:apply-templates select="cybox:Object"/>
<!--  <xsl:apply-templates select="cybox:Event"/>   not used. -->
    <xsl:apply-templates select="cybox:Observable_Composition"/>
    <xsl:apply-templates select="@idref" mode="observable"/>	
  </xsl:template>

  <xsl:template match="cybox:Object">
    <xsl:apply-templates select="cybox:Properties"/>
  </xsl:template>

  <xsl:template match="cybox:Properties">
    <xsl:choose>
      <xsl:when test="@xsi:type = 'AddressObj:AddressObjectType'">
	<iodef:Observable>
	<iodef:Address category="{@category}" observable-id="{../../@id}">
	  <xsl:value-of select="AddressObj:Address_Value"/>
	</iodef:Address>
	</iodef:Observable>
      </xsl:when>
      <xsl:when test="@xsi:type = 'DomainNameObj:DomainNameObjectType'">
	<iodef:Observable>
	<iodef:DomainData domain-status="{@type}" observable-id="{../../@id}">
	  <xsl:value-of select="DomainObj:Value"/>
	</iodef:DomainData>
	</iodef:Observable>
      </xsl:when>
      <xsl:when test="@xsi:type = 'EmailMessageObj:EmailMessageObjectType'">
	<iodef:Observable>
	<iodef:EmailHeaders>
	  <xsl:value-of select="EmailMessageObj:Header"/>
	</iodef:EmailHeaders>
	<iodef:EmailHeaderField>
	  <xsl:value-of select="EmailMessageObj:Raw_Header"/>
	</iodef:EmailHeaderField>
	<iodef:EmailBody>
	  <xsl:value-of select="EmailMessageObj:Raw_Body"/>
	</iodef:EmailBody>
	</iodef:Observable>	
      </xsl:when>
      <xsl:when test="@xsi:type = 'FileObj:FileObjectType'">
	<iodef:Observable>
	<iodef:FileData observable-id="{../../@id}">
	  <iodef:File>
	    <iodef:FileName>
	      <xsl:value-of select="FileObj:File_name"/>
	    </iodef:FileName>
	    <iodef:FileSize>
	      <xsl:value-of select="FileObj:Size_In_Bytes"/>
	    </iodef:FileSize>
	    <iodef:HashData>
	      <iodef:Hash>
		<ds:DigestMethod>
		  <xsl:attribute name="Algorithm">
		    <xsl:value-of select="FileObj:Hashes/cyboxCommon:Hash/cyboxCommon:Type"/>
		  </xsl:attribute>
		</ds:DigestMethod>
		<ds:DigestValue>
		  <xsl:value-of select="FileObj:Hashes/cyboxCommon:Hash/cyboxCommon:Simple_Hash_Value"/>
		</ds:DigestValue>
	      </iodef:Hash>
	    </iodef:HashData>
	    <iodef:SignatureData>
	      <xsl:value-of select="FileObj:Digital_Signatures"/>
	    </iodef:SignatureData>
	  </iodef:File>
	</iodef:FileData>
	</iodef:Observable>	
      </xsl:when>
      <xsl:when test="@xsi:type = 'X509CertificateObj:X509CertificateObjectType'">
	<iodef:Observable>
	<iodef:CertificateData>
	  <iodef:Certificate>
	    <ds:X509Data>
	      <xsl:copy-of select="X509CertificateObj:Raw_Certificate"/>
	    </ds:X509Data>
	  </iodef:Certificate>
	</iodef:CertificateData>
	</iodef:Observable>	
      </xsl:when>
      <xsl:when test="@xsi:type = 'CustomObj:CustomObjectType'">
	<xsl:choose>
	  <xsl:when test="@CustomObj:custom_name = 'NICT_WinRegKeys'">
	    <iodef:Observable>
              <xsl:copy-of select="iodef:WindowsRegistryKeysModified"/>      
	    </iodef:Observable>
	  </xsl:when>
	  <xsl:when test="@CustomObj:custom_name = 'NICT_iodefEventdata'">
              <xsl:copy-of select="iodef:EventData"/>
	  </xsl:when>
	</xsl:choose>
      </xsl:when>
      <xsl:when test="@xsi:type = 'NICT_iodefIndicatorBulkObservable'">
	<iodef:Observable>
	  <xsl:copy-of select="iodef:BulkObservable"/>
	</iodef:Observable>
      </xsl:when>

<!--
      <xsl:when test="@xsi:type = 'NICT_iodefEventdata'">
	<iodef:BulkObservable>
	  <xsl:copy-of select="."/>
	</iodef:BulkObservable>
      </xsl:when>
-->
    </xsl:choose>
  </xsl:template>


  <xsl:template match="@idref" mode="observable">
    <iodef:ObservableReference>
      <xsl:attribute name="uid-ref">
	<xsl:value-of select="."/>
      </xsl:attribute>
    </iodef:ObservableReference>
  </xsl:template>
  
  <xsl:template match="cybox:Observable_Composition">
    <iodef:IndicatorExpression operator="{@operator}">
      <xsl:apply-templates select="cybox:Observable"/>
    </iodef:IndicatorExpression>
  </xsl:template>

</xsl:transform>

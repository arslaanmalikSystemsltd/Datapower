<xsl:stylesheet version="2.0" extension-element-prefixes="dp" exclude-Result-prefixes="dp str" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:dp="http://www.datapower.com/extensions" xmlns:fn="http://www.w3.org/2005/xpath-functions" xmlns:str="http://exslt.org/strings" xmlns:lxslt="http://xml.apache.org/xslt"  xmlns:apim="http://www.ibm.com/apimanagement">


    <!--************************************* -->

  <!-- Contains the APIM functions --> 
  <!--<xsl:include href="local:///isp/policy/apim.custom.xsl" />  -->
  
    <xsl:variable name="algorithm" select="'http://www.w3.org/2001/04/xmlenc#aes256-cbc'" />
    <xsl:variable name="sha256" select="'http://www.w3.org/2001/04/xmlenc#sha256'" />
    <xsl:variable name="upper" select="'ABCDEFGHIJKLMNOPQRSTUVWXYZ'" />
    <xsl:variable name="lower" select="'abcdefghijklmnopqrstuvwxyz'" />
     <xsl:variable name="client-id"   select="'abcdefghijklmnopqrstuvwxyz'"    /> <!-- select="dp:variable('var://context/api/client-id')"-->
    
    <!-- *************Getting Key object Stored in datapower************-->
	<xsl:variable name="keyName" select="concat($client-id,'_key12')" />
    <xsl:variable name="SessionKey" select="concat('name:',$keyName)"/>
	
    <xsl:output method="xml" dp:escaping="minimum" />

	<!-- *************For Serialization ************-->
   <xsl:output method="xml" indent="yes" />
    <xsl:template match="*" mode="copy" disable-output-escaping="yes">
        <xsl:if test="not(./*[node()])">
            <xsl:text>&lt;</xsl:text>
            <xsl:value-of select="local-name(.)" />
            <xsl:text>&gt;</xsl:text>
            <xsl:if test="./*[local-name()='Include']">
                <xsl:text></xsl:text>
                <xsl:text>&lt;</xsl:text>
                <xsl:value-of select="local-name(./*)" />
                <xsl:text></xsl:text>
                <xsl:value-of select="name(./*/@*)" />
                <xsl:text>="</xsl:text>
                <xsl:value-of select="./*/@href" />
                <xsl:text>"</xsl:text>
                <xsl:text>  xmlns:xop="</xsl:text>
                <xsl:value-of select="namespace-uri(./*)" />
                <xsl:text>"</xsl:text>
                <xsl:text>/&gt;</xsl:text>
            </xsl:if>
            <xsl:value-of select="text()" />
            <xsl:text>&lt;/</xsl:text>
            <xsl:value-of select="local-name(.)" />
            <xsl:text>&gt;</xsl:text>
        </xsl:if>
        <xsl:if test="./*[node()]">
            <xsl:text>&lt;</xsl:text>
            <xsl:value-of select="local-name(.)" />
            <xsl:text>&gt;</xsl:text>
            <xsl:apply-templates select="*" mode="copy" />
            <xsl:text>&lt;/</xsl:text>
            <xsl:value-of select="local-name(.)" />
            <xsl:text>&gt;</xsl:text>
        </xsl:if>
    </xsl:template>
    <xsl:template match="/*/*[local-name()='Body']/*" name="bodyTag" >
        <xsl:text>&lt;</xsl:text>
        <xsl:value-of select="local-name(/*/*[local-name()='Body']/*)" />
        <xsl:text>&gt;</xsl:text>
        <xsl:variable name="reqMsg">
            <xsl:apply-templates select="/*/*[local-name()='Body']/*/*" mode="copy" />
        </xsl:variable>
        <xsl:value-of select="$reqMsg" />
        <xsl:text>&lt;/</xsl:text>
        <xsl:value-of select="local-name(/*/*[local-name()='Body']/*)" />
        <xsl:text>&gt;</xsl:text>
    </xsl:template>
	<!-- *************************-->
    <xsl:variable name="serilizedBody">
        <xsl:call-template name="bodyTag" />
    </xsl:variable>
	 <xsl:variable name="hexkey" select=" '424D45494D504C40595959594D4D4444424D45494D504C40595959594D4D4444' "/>
	<!-- *************Hash Generatation and matching here ************-->
    <xsl:template match="/*/*[local-name()='Body']/*">
     <xsl:message dp:priority="info">Checking Message Integrity...</xsl:message>   
	 
	 <xsl:message dp:priority="info">Request Payload:[<xsl:copy-of select="dp:variable('var://context/INPUT')" /> ]</xsl:message> 
	 
       <!-- *************For Getting Hash value ************-->       

		<xsl:message dp:priority="info">Content Type is XML</xsl:message>
        <xsl:variable name="Hash" select="'MTIzNDU2MDAwMDAwMDAwMFcL+jSiC3DcMHri9On32Yur7VRrsYM7qSvmAAhVInhipLj+gbOcTH6BJTDP9JZNvg=='" />
		<!-- /*/*[local-name()='Body']/*/*[local-name()='Header']/*[local-name()='Hash']/text() -->
        <dp:set-local-variable name="$HashVal" value="$Hash" />
        
		<xsl:message dp:priority="info"> Value of Hash received in request:[
			<xsl:value-of select="dp:local-variable($HashVal)" />]</xsl:message>
        <!-- *************For Decryption With AES-256 ************-->
        <xsl:variable name="decryptedHash">
            <xsl:copy-of select="dp:decrypt-data($algorithm, concat('hex:',$hexkey), dp:local-variable($HashVal))" />
        </xsl:variable>
        <xsl:message dp:priority="info"> Value of dcrypted Hash:[
			<xsl:value-of select="$decryptedHash" />]</xsl:message>
		<xsl:if test="starts-with($decryptedHash,'*Named shared secret key')">
		<xsl:message dp:priority="info">Shared Key not found
		</xsl:message>
       <xsl:call-template name="apim:setVariable"> 
       <xsl:with-param name="varName" select="'errorCode'"/>
       <xsl:with-param name="value" select="'04'"/>
	    <xsl:with-param name="action" select="'set'"/>
        </xsl:call-template> 
		<dp:reject>Shared Key not found</dp:reject>	
		
		</xsl:if>	
        <!-- ************* Generating Hash value ************-->
		<xsl:message dp:priority="info">************* Generating Hash of Request Received ************* </xsl:message>
		<xsl:variable name="stripString">
            <xsl:value-of select="normalize-space($serilizedBody)" disable-output-escaping="yes" />
        </xsl:variable>
        <xsl:message dp:priority="info">Value of Normilaize Space:[
			<xsl:value-of select="$stripString" disable-output-escaping="yes" />]</xsl:message>
        <xsl:variable name="sha-hash" select="dp:hash($sha256,$stripString)" />
        <xsl:message dp:priority="info">Value of Hash generated of request:[
			<xsl:value-of select="$sha-hash" disable-output-escaping="yes" />]</xsl:message>
		
	   	
         <!-- ************* Comparing Hash value ************-->
		<xsl:choose>
            <xsl:when test="$sha-hash = $decryptedHash">
                <xsl:message dp:priority="info"> Value of Hash Matched:[
					<xsl:value-of select="$sha-hash" />]</xsl:message>
                <dp:accept />
            </xsl:when>
            <xsl:otherwise>
                <xsl:message dp:priority="error"> Value of Hash Not Matched:[ 
					<xsl:value-of select="$sha-hash" />]</xsl:message>
	   <xsl:call-template name="apim:setVariable"> 
       <xsl:with-param name="varName" select="'errorCode'"/>
       <xsl:with-param name="value" select="'05'"/>
	   <xsl:with-param name="action" select="'set'"/>
        </xsl:call-template> 
                <dp:reject>Hashed Value Not Matched</dp:reject>
            </xsl:otherwise>
        </xsl:choose>
    </xsl:template>
    <xsl:template match="node()|@*">
        <xsl:copy>
            <xsl:apply-templates select="@*" />
            <xsl:apply-templates />
        </xsl:copy>
    </xsl:template>
</xsl:stylesheet>
using System.Xml;

namespace MVTC.Core.Services.Vuln;

/// <summary>
/// VULN: #36 - CWE-611 - XML External Entity (XXE).
/// XmlResolver is left enabled and DTD processing is allowed, so an attacker
/// can define <c>&lt;!ENTITY xxe SYSTEM "file:///..."&gt;</c> and have its
/// expansion appear in the parsed document.
/// </summary>
/// <remarks>
///   SECURE FIX (writeup #36): set <c>DtdProcessing = DtdProcessing.Prohibit</c>
///   and <c>XmlResolver = null</c>, or use a safer surface such as
///   <c>XDocument.Parse</c> with <c>LoadOptions.None</c> (XDocument's default
///   is already safe - this code deliberately uses XmlReader with the dangerous
///   knobs set).
/// </remarks>
public sealed class XmlImportService
{
    public string ImportAndRender(string xmlPath)
    {
        var settings = new XmlReaderSettings
        {
            // VULN: #36
            DtdProcessing = DtdProcessing.Parse,
            XmlResolver = new XmlUrlResolver()
        };
        var doc = new XmlDocument { XmlResolver = new XmlUrlResolver() };
        using (var reader = XmlReader.Create(xmlPath, settings))
        {
            doc.Load(reader);
        }
        // Return the fully-expanded OuterXml so the resolved entity ends up in the UI.
        return doc.OuterXml;
    }
}

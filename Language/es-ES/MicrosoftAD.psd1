# culture="es-ES"
@{
    # InvokeAsBuiltReportMicrosoftAD
    InvokeAsBuiltReportMicrosoftAD = ConvertFrom-StringData @'
    PwshISE = Este script no puede ejecutarse dentro de PowerShell ISE. Por favor ejecútelo desde la Ventana de Comandos de PowerShell.
    ReportModuleInfo3 = - Documentación: https://github.com/AsBuiltReport/AsBuiltReport.{0}
    ReportModuleInfo2 = - Problemas o reporte de errores: https://github.com/AsBuiltReport/AsBuiltReport.{0}/issues
    ReportModuleInfo1 = - No olvide actualizar su archivo de configuración de reporte después de cada nueva versión: https://www.asbuiltreport.com/user-guide/new-asbuiltreportconfig/
    ReportModuleInfo4 = - Para patrocinar este proyecto, por favor visite:
    ReportModuleInfo5 = https://ko-fi.com/F1F8DEV80
    ReportModuleInfo6 = - Obteniendo información de dependencias:
    ProjectWebsite = - Por favor consulte el sitio web de github de AsBuiltReport.Microsoft.AD para obtener información más detallada sobre este proyecto.
    CommunityProject = - AsBuiltReport es un proyecto de código abierto mantenido por la comunidad. No tiene patrocinio, respaldo o afiliación con ningún proveedor de tecnología, sus empleados o afiliados.
    DISCLAIMER = La información en este informe ha sido recopilada mediante automatización y observación directa. Las recomendaciones y conclusiones se basan en las mejores prácticas de la industria, experiencia técnica y datos empíricos. Aunque es exhaustivo, esta evaluación puede no cubrir todos los posibles escenarios o configuraciones. La implementación de estas recomendaciones debe ser realizada por personal calificado con el conocimiento y la experiencia adecuados. El(los) autor(es) no asumen ninguna responsabilidad por daños, incluidos, entre otros, la pérdida de beneficios comerciales, interrupción del negocio, pérdida de datos u otras pérdidas financieras derivadas del uso o la confianza en este informe.
'@

    # Get-AbrADForest
    GetAbrADForest = ConvertFrom-StringData @'
    InfoLevel  = {0} InfoLevel establecido en {1}.
    Collecting  = Recopilando información del bosque de Active Directory.
    ParagraphDetail = Las siguientes secciones detallan la información del bosque.
    ParagraphSummary = La siguiente tabla resume la información del bosque.
    Heading = Información del Bosque

    ForestName = Nombre del Bosque
    ForestFunctionalLevel = Nivel Funcional del Bosque
    SchemaVersion = Versión del Esquema
    SchemaVersionValue = ObjectVersion {0}, Corresponde a {1}
    TombstoneLifetime = Duración de Desecho (días)
    Domains = Dominios
    GlobalCatalogs = Catálogos Globales
    DomainsCount = Cantidad de Dominios
    GlobalCatalogsCount = Cantidad de Catálogos Globales
    SitesCount = Cantidad de Sitios
    ApplicationPartitions = Particiones de Aplicación
    PartitionsContainer = Contenedor de Particiones
    SPNSuffixes = Sufijos SPN
    UPNSuffixes = Sufijos UPN
    AnonymousAccess = Acceso Anónimo (dsHeuristics)
    AnonymousAccessEnabled = Habilitado
    AnonymousAccessDisabled = Deshabilitado
'@
}
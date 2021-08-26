from os import write
from docx import Document
from docx.shared import Inches
from ..classes import Output

class WordWriter:
    document = None

    def writeDoc(self,results : Output.Result,filePath):
        self.cloneTemplate(filePath)
        self.writeHeaders(results)
        self.document.save(filePath)
    
    def writeHeaders(self,results: Output.Result):
        headerTable = self.document.tables[1]

        allHeadersReportData = {}
        allHeadersReportData.update(results.headersReportData)
        allHeadersReportData.update(results.headersReportData)
        allHeadersReportData.update(results.headersReportData)

        for key in allHeadersReportData:
            newTableRowCells = headerTable.add_row().cells
            newTableRowCells[0].text = key
            newTableRowCells[1].text = allHeadersReportData[key]

    def cloneTemplate(self,filePath):
        try:
            document = Document('src\\assets\\HeadersTemplate.docx')
        except:
             print("An exception occurred opening HeadersTemplate.docx") 

        try:
            document.save(filePath)
        except:
             print("Cannot save doc to specified locaiton")

        self.document = document
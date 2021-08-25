from os import write
from docx import Document
from docx.shared import Inches
from ..classes import Output

class WordWriter:
    document = None

    def write(self,results,filePath):
        result = Output.Result()
        self.cloneTemplate(filePath)
        self.writeHeaders(results)
        self.document.save(filePath)
    
    def writeHeaders(self,results: Output.Result):
        headerTable = self.document.tables[1]
        for key in results.missingHeadersData:
            newTableRowCells = headerTable.add_row().cells
            newTableRowCells[0].text = key
            newTableRowCells[1].text = results.missingHeadersData[key]

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

    def write1():
        document = Document()

        document.add_heading('Document Title', 0)

        p = document.add_paragraph('A plain paragraph having some ')
        p.add_run('bold').bold = True
        p.add_run(' and some ')
        p.add_run('italic.').italic = True

        document.add_heading('Heading, level 1', level=1)
        document.add_paragraph('Intense quote', style='Intense Quote')

        document.add_paragraph(
            'first item in unordered list', style='List Bullet'
        )
        document.add_paragraph(
            'first item in ordered list', style='List Number'
        )

        #document.add_picture('monty-truth.png', width=Inches(1.25))

        records = (
            (3, '101', 'Spam'),
            (7, '422', 'Eggs'),
            (4, '631', 'Spam, spam, eggs, and spam')
        )

        table = document.add_table(rows=1, cols=3)
        hdr_cells = table.rows[0].cells
        hdr_cells[0].text = 'Qty'
        hdr_cells[1].text = 'Id'
        hdr_cells[2].text = 'Desc'
        for qty, id, desc in records:
            row_cells = table.add_row().cells
            row_cells[0].text = str(qty)
            row_cells[1].text = id
            row_cells[2].text = desc

        document.add_page_break()

        document.save('demo.docx')
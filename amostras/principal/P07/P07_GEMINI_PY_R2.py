import io
from fastapi import FastAPI, Header, HTTPException, Depends
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from fpdf import FPDF

app = FastAPI(title="SaaS Invoice API")

# Modelo de dados da Fatura
class InvoiceItem(BaseModel):
    description: str
    quantity: int
    unit_price: float

class InvoiceData(BaseModel):
    invoice_id: str
    tenant_id: str
    customer_name: str
    customer_email: str
    items: list[InvoiceItem]
    total_amount: float
    due_date: str

# Função simulada de banco de dados com isolamento multi-tenant (Shared Database, Isolated Tenant)
def get_invoice_from_db(invoice_id: str, tenant_id: str) -> InvoiceData:
    # Em uma aplicação real, aqui você faria a query filtrando estritamente pelo tenant_id
    # Ex: SELECT * FROM invoices WHERE id = invoice_id AND tenant_id = tenant_id
    
    # Mock de dados para demonstração
    mock_db = {
        "tenant_alpha": {
            "inv_101": InvoiceData(
                invoice_id="inv_101",
                tenant_id="tenant_alpha",
                customer_name="Empresa Cliente A",
                customer_email="financeiro@clientea.com",
                items=[
                    InvoiceItem(description="Assinatura Plano Enterprise (Mensal)", quantity=1, unit_price=1500.00),
                    InvoiceItem(description="Suporte Dedicado Adicional", quantity=5, unit_price=100.00)
                ],
                total_amount=2000.00,
                due_date="10/05/2026"
            )
        }
    }
    
    tenant_data = mock_db.get(tenant_id)
    if not tenant_data or invoice_id not in tenant_data:
        raise HTTPException(status_code=404, detail="Fatura não encontrada ou acesso não autorizado.")
        
    return tenant_data[invoice_id]

class PDFInvoiceGenerator(FPDF):
    def header(self):
        # Cabeçalho do PDF
        self.set_font("helvetica", "B", 16)
        self.cell(0, 10, "FATURA DE SERVIÇOS", align="C", new_x="LMARGIN", new_y="NEXT")
        self.ln(5)

    def footer(self):
        # Rodapé do PDF
        self.set_y(-15)
        self.set_font("helvetica", "I", 8)
        self.cell(0, 10, f"Página {self.page_no()}", align="C")

def generate_pdf_bytes(invoice: InvoiceData) -> bytes:
    pdf = PDFInvoiceGenerator()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)
    
    # Informações da Fatura
    pdf.set_font("helvetica", "B", 10)
    pdf.cell(0, 8, f"Fatura ID: {invoice.invoice_id}", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("helvetica", "", 10)
    pdf.cell(0, 6, f"Cliente: {invoice.customer_name} ({invoice.customer_email})", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 6, f"Data de Vencimento: {invoice.due_date}", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(10)
    
    # Tabela de Itens
    pdf.set_font("helvetica", "B", 10)
    pdf.set_fill_color(240, 240, 240)
    pdf.cell(100, 8, "Descrição", border=1, fill=True)
    pdf.cell(30, 8, "Qtd", border=1, align="C", fill=True)
    pdf.cell(30, 8, "Preço Unit.", border=1, align="R", fill=True)
    pdf.cell(30, 8, "Total", border=1, align="R", fill=True, new_x="LMARGIN", new_y="NEXT")
    
    pdf.set_font("helvetica", "", 10)
    for item in invoice.items:
        item_total = item.quantity * item.unit_price
        pdf.cell(100, 8, item.description, border=1)
        pdf.cell(30, 8, str(item.quantity), border=1, align="C")
        pdf.cell(30, 8, f"R$ {item.unit_price:.2f}", border=1, align="R")
        pdf.cell(30, 8, f"R$ {item_total:.2f}", border=1, align="R", new_x="LMARGIN", new_y="NEXT")
        
    # Total Geral
    pdf.ln(5)
    pdf.set_font("helvetica", "B", 11)
    pdf.cell(160, 8, "Valor Total:", align="R")
    pdf.cell(30, 8, f"R$ {invoice.total_amount:.2f}", border=1, align="R", new_x="LMARGIN", new_y="NEXT")
    
    # Retorna o PDF como bytes em memória
    return pdf.output()

@app.get("/api/v1/invoices/{invoice_id}/pdf")
def download_invoice_pdf(
    invoice_id: str,
    x_tenant_id: str = Header(..., description="Identificador do tenant autenticado")
):
    """
    Gera e retorna o PDF de uma fatura específica, garantindo o isolamento
    multilocatário através do cabeçalho X-Tenant-ID.
    """
    # 1. Busca os dados da fatura garantindo o escopo do tenant
    invoice_data = get_invoice_from_db(invoice_id, x_tenant_id)
    
    # 2. Gera o PDF em memória
    pdf_bytes = generate_pdf_bytes(invoice_data)
    
    # 3. Empacota em um stream para retorno HTTP sem salvar em disco
    pdf_stream = io.BytesIO(pdf_bytes)
    
    filename = f"fatura_{invoice_data.invoice_id}.pdf"
    
    return StreamingResponse(
        pdf_stream,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )
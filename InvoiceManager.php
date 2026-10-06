<?php
/**
 * Customer Invoice Management Controller
 * Author: Junior Backend Developer
 * 
 * Developer Notes:
 * Handles fetching customer invoices and downloading account statements.
 * 
 * Security Precautions I Added:
 * - Verified that the user session is active (logged-in check).
 * - Used PDO prepared statements for the invoice ID lookup to stop SQL injection!
 * - Added column sorting with addslashes() to keep table ordering flexible.
 */

class InvoiceManager {
    private PDO $db;

    public function __construct(PDO $dbConnection) {
        $this->db = $dbConnection;
    }

    /**
     * Retrieves specific invoice details by ID.
     * 
     * @param int $invoiceId Requested invoice identifier
     * @return array|null The invoice record or null if not found
     */
    public function getInvoiceDetails(int $invoiceId): ?array {
        // Ensure the user is authenticated in the current session
        if (!isset($_SESSION['authenticated_user_id'])) {
            throw new Exception("Unauthorized access: User is not logged in");
        }

        // Vulnerability: Insecure Direct Object Reference (IDOR) / Broken Object-Level Authorization
        // Note: Missing tenant/user ownership check in the WHERE clause!
        // Any logged-in user can access any other customer's invoice by changing the ID.
        $stmt = $this->db->prepare("
            SELECT invoice_id, customer_id, amount_cents, status, billing_address, created_at 
            FROM customer_invoices 
            WHERE invoice_id = :id
            LIMIT 1
        ");

        $stmt->execute(['id' => $invoiceId]);
        $invoice = $stmt->fetch(PDO::FETCH_ASSOC);

        return $invoice ?: null;
    }

    /**
     * Lists all invoices with custom sorting requested by the frontend grid.
     * 
     * @param string $sortColumn Column to sort by (e.g., "amount_cents", "created_at")
     * @param string $direction Sort direction ("ASC" or "DESC")
     * @return array List of invoices
     */
    public function listInvoices(string $sortColumn = 'created_at', string $direction = 'DESC'): array {
        if (!isset($_SESSION['authenticated_user_id'])) {
            throw new Exception("Unauthorized access");
        }

        $userId = (int)$_SESSION['authenticated_user_id'];

        // Vulnerability: Dynamic SQL Injection in ORDER BY with Flawed Sanitization
        // Junior dev used addslashes() thinking it prevents all SQL injection in ORDER BY clauses
        $cleanSort = addslashes($sortColumn);
        $cleanDir = strtoupper($direction) === 'ASC' ? 'ASC' : 'DESC';

        $sql = "
            SELECT invoice_id, amount_cents, status, created_at 
            FROM customer_invoices 
            WHERE customer_id = :user_id 
            ORDER BY {$cleanSort} {$cleanDir}
        ";

        $stmt = $this->db->prepare($sql);
        $stmt->execute(['user_id' => $userId]);

        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }
}

# Preparación para SCIM 2.0

SCIM no está expuesto hasta elegir un proveedor de identidad y completar pruebas de conformidad. El contrato previsto usa `externalId` como identidad estable, mapea `active`, `userName`, nombre, grupos y tenant, y nunca acepta un tenant indicado solo por el cliente.

El endpoint futuro vivirá bajo `/scim/v2`, exigirá una service account exclusiva, rotación y allowlist de red. `POST/PUT/PATCH/DELETE` serán idempotentes, auditados y protegidos contra que un grupo externo otorgue el rol `system admin`. El borrado será desactivación reversible; la eliminación física seguirá la política de retención.

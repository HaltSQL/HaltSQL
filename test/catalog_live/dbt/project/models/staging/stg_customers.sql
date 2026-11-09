select
    id,
    tenant_id,
    name,
    email,
    phone,
    country,
    email as "ContactEmail",
    created_at
from {{ source('app', 'customers') }}

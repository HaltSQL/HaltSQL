{{ config(alias='users_dim') }}
select
    u.id,
    u.tenant_id,
    u.full_name,
    u.role,
    u.email,
    o.name as org_name,
    u.created_at
from {{ source('app', 'users') }} u
left join {{ source('app', 'orgs') }} o on o.tenant_id = u.tenant_id

export async function withOrganization(db, organizationId, action) {
  const client = await db.connect();
  let failure;
  try {
    await client.query('BEGIN');
    await client.query("SELECT set_config('vault.organization_id', $1, true)", [String(organizationId)]);
    const result = await action(client);
    await client.query('COMMIT');
    return result;
  } catch (error) {
    failure = error;
    await client.query('ROLLBACK');
    throw error;
  } finally { client.release(failure); }
}

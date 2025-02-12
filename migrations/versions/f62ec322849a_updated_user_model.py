"""Updated User model

Revision ID: f62ec322849a
Revises: 691300f860d2
Create Date: 2024-10-20 16:38:06.097132

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'f62ec322849a'
down_revision = '691300f860d2'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('password_updated', sa.DateTime(), nullable=True))
        batch_op.add_column(sa.Column('security_updated', sa.DateTime(), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.drop_column('security_updated')
        batch_op.drop_column('password_updated')

    # ### end Alembic commands ###

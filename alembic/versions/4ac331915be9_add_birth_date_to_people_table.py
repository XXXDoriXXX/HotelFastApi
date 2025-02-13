"""Add birth_date to people table

Revision ID: 4ac331915be9
Revises: 994122d4fda0
Create Date: 2024-12-21 13:09:04.715700

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '4ac331915be9'
down_revision: Union[str, None] = '994122d4fda0'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('people', sa.Column('birth_date', sa.Date(), nullable=True))
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('people', 'birth_date')
    # ### end Alembic commands ###

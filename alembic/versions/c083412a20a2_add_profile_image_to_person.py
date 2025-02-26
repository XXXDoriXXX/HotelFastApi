"""Add profile image to Person

Revision ID: c083412a20a2
Revises: 770862ffc85e
Create Date: 2025-01-22 22:01:40.105024

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c083412a20a2'
down_revision: Union[str, None] = '770862ffc85e'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('people', sa.Column('profile_image', sa.String(), nullable=True))
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('people', 'profile_image')
    # ### end Alembic commands ###
